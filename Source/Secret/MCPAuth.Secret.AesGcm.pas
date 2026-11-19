unit MCPAuth.Secret.AesGcm;

interface

uses
  System.SysUtils,
  TaurusTLSHeaders_types,
  MCPAuth.Secret.Interfaces;

type
  // Envelope layout: version (1 byte) | key id length (1 byte) | key id (UTF-8) | nonce (12 bytes) | ciphertext | tag (16 bytes).
  // The context is bound to the envelope as additional authenticated data.
  TAesGcmProtector = class(TInterfacedObject, ISecretProtector)
  private type
    TEnvelope = record
      KeyId: string;
      Nonce: TBytes;
      Sealed: TBytes;
    end;

  private
    FKeyRing: IKeyRing;

    procedure GuardKeyRing(const KeyRing: IKeyRing);
    function GetCurrentKey: TBytes;
    function Seal(const Key, Nonce, Plain, Aad: TBytes): TBytes;
    function BuildEnvelope(const KeyId: string; const Nonce, Sealed: TBytes): TBytes;
    function TryParseEnvelope(const Envelope: TBytes; out Parts: TEnvelope): Boolean;
    function TryOpen(const Key, Nonce, Sealed, Aad: TBytes; out Plain: TBytes): Boolean;
    function StartCipher(const Key, Nonce, Aad: TBytes; const Direction: Integer): PEVP_CIPHER_CTX;
    procedure InitializeCipher(const CipherContext: PEVP_CIPHER_CTX; const Key, Nonce, Aad: TBytes; const Direction: Integer);
    procedure CheckStep(const OpenSslResult: Integer);

  public
    constructor Create(const KeyRing: IKeyRing);

    function Protect(const Plain, Context: string): TBytes;
    function Unprotect(const Envelope: TBytes; const Context: string): string;
    function NeedsRewrap(const Envelope: TBytes): Boolean;
  end;

implementation

uses
  IdCTypes,
  TaurusTLSHeaders_evp,
  MCPAuth.Secret.OpenSsl;

const
  EnvelopeVersion = 1;
  FixedHeaderLength = 2;
  MaxKeyIdLength = 255;
  NonceLength = 12;
  TagLength = 16;
  OpenSslSuccess = 1;
  DirectionDecrypt = 0;
  DirectionEncrypt = 1;

resourcestring
  KeyRingMissing = 'A secret protector needs a key ring';
  UnprotectFailed = 'The protected secret could not be decrypted';
  CipherFailed = 'OpenSSL AES-256-GCM operation failed';
  CipherContextFailed = 'OpenSSL could not create a cipher context';
  CurrentKeyMissing = 'The key ring has no key for the current key id';
  KeyIdNotValid = 'A key id must have 1 to 255 UTF-8 bytes';

{ TAesGcmProtector }

constructor TAesGcmProtector.Create(const KeyRing: IKeyRing);
begin
  inherited Create;
  GuardKeyRing(KeyRing);
  FKeyRing := KeyRing;
end;

procedure TAesGcmProtector.GuardKeyRing(const KeyRing: IKeyRing);
begin
  if not Assigned(KeyRing) then
    raise ESecretConfigurationError.Create(KeyRingMissing);
end;

function TAesGcmProtector.Protect(const Plain, Context: string): TBytes;
begin
  const KeyId = FKeyRing.CurrentKeyId;
  const Key = GetCurrentKey;
  const Nonce = TOpenSsl.RandomBytes(NonceLength);
  const PlainBytes = TEncoding.UTF8.GetBytes(Plain);
  const Aad = TEncoding.UTF8.GetBytes(Context);

  const Sealed = Seal(Key, Nonce, PlainBytes, Aad);

  Result := BuildEnvelope(KeyId, Nonce, Sealed);
end;

function TAesGcmProtector.Unprotect(const Envelope: TBytes; const Context: string): string;
begin
  var Parts: TEnvelope;
  const IsWellFormed = TryParseEnvelope(Envelope, Parts);
  if not IsWellFormed then
    raise ESecretUnprotectError.Create(UnprotectFailed);

  var Key: TBytes;
  const HasKey = FKeyRing.TryGetKey(Parts.KeyId, Key);
  if not HasKey then
    raise ESecretUnprotectError.Create(UnprotectFailed);

  const Aad = TEncoding.UTF8.GetBytes(Context);
  var Plain: TBytes;
  const IsAuthentic = TryOpen(Key, Parts.Nonce, Parts.Sealed, Aad, Plain);
  if not IsAuthentic then
    raise ESecretUnprotectError.Create(UnprotectFailed);

  Result := TEncoding.UTF8.GetString(Plain);
end;

function TAesGcmProtector.NeedsRewrap(const Envelope: TBytes): Boolean;
begin
  var Parts: TEnvelope;
  const IsWellFormed = TryParseEnvelope(Envelope, Parts);
  if not IsWellFormed then
    raise ESecretUnprotectError.Create(UnprotectFailed);

  Result := (Parts.KeyId <> FKeyRing.CurrentKeyId);
end;

function TAesGcmProtector.GetCurrentKey: TBytes;
begin
  const KeyId = FKeyRing.CurrentKeyId;
  const HasKey = FKeyRing.TryGetKey(KeyId, Result);
  if not HasKey then
    raise ESecretConfigurationError.Create(CurrentKeyMissing);
end;

function TAesGcmProtector.Seal(const Key, Nonce, Plain, Aad: TBytes): TBytes;
begin
  const PlainLength = Length(Plain);
  const HasPlain = (PlainLength > 0);
  SetLength(Result, PlainLength + TagLength);

  const CipherContext = StartCipher(Key, Nonce, Aad, DirectionEncrypt);
  try
    var Written: TIdC_INT;
    if HasPlain then
    begin
      const Encrypted = EVP_CipherUpdate(CipherContext, Result[0], Written, Plain[0], PlainLength);
      CheckStep(Encrypted);
    end;

    const Finalized = EVP_CipherFinal_ex(CipherContext, Result[PlainLength], Written);
    CheckStep(Finalized);

    const TagWritten = EVP_CIPHER_CTX_ctrl(CipherContext, EVP_CTRL_GCM_GET_TAG, TagLength, @Result[PlainLength]);
    CheckStep(TagWritten);
  finally
    EVP_CIPHER_CTX_free(CipherContext);
  end;
end;

function TAesGcmProtector.BuildEnvelope(const KeyId: string; const Nonce, Sealed: TBytes): TBytes;
begin
  const KeyIdBytes = TEncoding.UTF8.GetBytes(KeyId);
  const KeyIdLength = Length(KeyIdBytes);
  const IsValidKeyId = ((KeyIdLength > 0) and (KeyIdLength <= MaxKeyIdLength));
  if not IsValidKeyId then
    raise ESecretConfigurationError.Create(KeyIdNotValid);

  Result := [EnvelopeVersion, Byte(KeyIdLength)] + KeyIdBytes + Nonce + Sealed;
end;

function TAesGcmProtector.TryParseEnvelope(const Envelope: TBytes; out Parts: TEnvelope): Boolean;
begin
  const EnvelopeLength = Length(Envelope);
  const HasFixedHeader = (EnvelopeLength >= FixedHeaderLength);
  if not HasFixedHeader then
    Exit(False);

  const IsKnownVersion = (Envelope[0] = EnvelopeVersion);
  const KeyIdLength = Integer(Envelope[1]);
  const NonceStart = FixedHeaderLength + KeyIdLength;
  const SealedStart = NonceStart + NonceLength;
  const IsLongEnough = (EnvelopeLength >= SealedStart + TagLength);
  const IsWellFormed = (IsKnownVersion and (KeyIdLength > 0) and IsLongEnough);
  if not IsWellFormed then
    Exit(False);

  Parts.KeyId  := TEncoding.UTF8.GetString(Envelope, FixedHeaderLength, KeyIdLength);
  Parts.Nonce  := Copy(Envelope, NonceStart, NonceLength);
  Parts.Sealed := Copy(Envelope, SealedStart, EnvelopeLength - SealedStart);
  Result := True;
end;

function TAesGcmProtector.TryOpen(const Key, Nonce, Sealed, Aad: TBytes; out Plain: TBytes): Boolean;
begin
  const CiphertextLength = Length(Sealed) - TagLength;
  const HasCiphertext = (CiphertextLength > 0);
  const Tag = Copy(Sealed, CiphertextLength, TagLength);
  SetLength(Plain, CiphertextLength);

  const CipherContext = StartCipher(Key, Nonce, Aad, DirectionDecrypt);
  try
    var Written: TIdC_INT;
    if HasCiphertext then
    begin
      const Decrypted = EVP_CipherUpdate(CipherContext, Plain[0], Written, Sealed[0], CiphertextLength);
      CheckStep(Decrypted);
    end;

    const TagSet = EVP_CIPHER_CTX_ctrl(CipherContext, EVP_CTRL_GCM_SET_TAG, TagLength, PByte(Tag));
    CheckStep(TagSet);

    // GCM writes no output on finalization; the call only verifies the tag.
    var FinalBlock: array[0..TagLength - 1] of Byte;
    const Verified = EVP_CipherFinal_ex(CipherContext, FinalBlock, Written);
    Result := (Verified = OpenSslSuccess);
  finally
    EVP_CIPHER_CTX_free(CipherContext);
  end;
end;

function TAesGcmProtector.StartCipher(const Key, Nonce, Aad: TBytes; const Direction: Integer): PEVP_CIPHER_CTX;
begin
  TOpenSsl.EnsureLoaded;

  Result := EVP_CIPHER_CTX_new();
  if not Assigned(Result) then
    raise ESecretError.Create(CipherContextFailed);

  try
    InitializeCipher(Result, Key, Nonce, Aad, Direction);
  except
    EVP_CIPHER_CTX_free(Result);
    raise;
  end;
end;

procedure TAesGcmProtector.InitializeCipher(const CipherContext: PEVP_CIPHER_CTX; const Key, Nonce, Aad: TBytes; const Direction: Integer);
begin
  const Cipher = EVP_aes_256_gcm();
  const CipherSet = EVP_CipherInit_ex(CipherContext, Cipher, nil, nil, nil, Direction);
  CheckStep(CipherSet);

  const NonceLengthSet = EVP_CIPHER_CTX_ctrl(CipherContext, EVP_CTRL_GCM_SET_IVLEN, NonceLength, nil);
  CheckStep(NonceLengthSet);

  const KeySet = EVP_CipherInit_ex(CipherContext, nil, nil, PByte(Key), PByte(Nonce), Direction);
  CheckStep(KeySet);

  // An update without output buffer passes additional authenticated data; PByte(nil)^ hands OpenSSL that nil buffer.
  var Written: TIdC_INT;
  const AadSet = EVP_CipherUpdate(CipherContext, PByte(nil)^, Written, PByte(Aad)^, Length(Aad));
  CheckStep(AadSet);
end;

procedure TAesGcmProtector.CheckStep(const OpenSslResult: Integer);
begin
  const Succeeded = (OpenSslResult = OpenSslSuccess);
  if not Succeeded then
    raise ESecretError.Create(CipherFailed);
end;

end.
