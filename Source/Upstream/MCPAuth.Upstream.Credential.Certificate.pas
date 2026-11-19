unit MCPAuth.Upstream.Credential.Certificate;

interface

uses
  System.SysUtils,
  Spring.Collections,
  TaurusTLSHeaders_types,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Secret.Interfaces,
  MCPAuth.Upstream.Interfaces;

type
  // Authenticates with a client_assertion JWT (RFC 7523) signed with RS256 by
  // the private key of a certificate. The PEM file holds the certificate and
  // its unencrypted RSA private key.
  TCertificateCredential = class(TInterfacedObject, IClientCredential)
  private
    FClientId: string;
    FClock: IClock;
    FTokenGenerator: ITokenGenerator;
    FPrivateKey: PEVP_PKEY;
    FThumbprint: string;

    procedure LoadPem(const PemPath: string);
    function ReadPemFile(const PemPath: string): TBytes;
    function ReadCertificate(const PemBytes: TBytes; const PemPath: string): PX509;
    function CertificateThumbprint(const Certificate: PX509): string;
    function ReadPrivateKey(const PemBytes: TBytes; const PemPath: string): PEVP_PKEY;
    procedure GuardRsaKey(const PemPath: string);
    procedure GuardKeyMatchesCertificate(const Certificate: PX509; const PemPath: string);

    function BuildAssertion(const TokenUrl: string): string;
    function HeaderJson: string;
    function ClaimsJson(const TokenUrl: string): string;
    function EncodePart(const Json: string): string;
    function Sign(const SigningInput: string): string;
    procedure CheckSignStep(const Succeeded: Boolean);

  public
    class function FromPemFile(const ClientId, PemPath: string): IClientCredential; overload; static;
    class function FromPemFile(const ClientId, PemPath: string; const Clock: IClock; const TokenGenerator: ITokenGenerator): IClientCredential; overload; static;

    constructor Create(const ClientId, PemPath: string; const Clock: IClock; const TokenGenerator: ITokenGenerator);
    destructor Destroy; override;

    function WithCredential(const TokenUrl: string; const Fields: TArray<TPair<string, string>>): TArray<TPair<string, string>>;
  end;

implementation

uses
  System.Classes,
  System.IOUtils,
  System.Hash,
  System.JSON,
  System.DateUtils,
  System.NetEncoding,
  IdCTypes,
  TaurusTLSHeaders_bio,
  TaurusTLSHeaders_err,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_pem,
  TaurusTLSHeaders_x509,
  MCPAuth.Clock,
  MCPAuth.Secret.Token,
  MCPAuth.Secret.OpenSsl,
  MCPAuth.Upstream.Exceptions;

const
  AssertionLifetimeSeconds = 300;
  JwtBearerAssertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

  // OpenSSL prompts on the console for the passphrase of an encrypted key when
  // neither a callback nor a passphrase is given; an empty passphrase avoids that.
  NoPassphrase: array[0..0] of AnsiChar = (#0);

resourcestring
  PemFileNotFound = 'The client certificate file "%s" does not exist';
  PemFileUnreadable = 'The client certificate file "%s" could not be read';
  PemCertificateMissing = 'The client certificate file "%s" does not contain a PEM certificate';
  PemPrivateKeyMissing = 'The client certificate file "%s" does not contain an unencrypted PEM private key';
  PemKeyNotRsa = 'The private key in the client certificate file "%s" is not an RSA key';
  PemKeyMismatch = 'The private key in the client certificate file "%s" does not belong to its certificate';
  AssertionSigningFailed = 'Signing the client assertion failed';

{ TCertificateCredential }

class function TCertificateCredential.FromPemFile(const ClientId, PemPath: string): IClientCredential;
begin
  const Clock: IClock = TSystemClock.Create;
  const TokenGenerator: ITokenGenerator = TTokenGenerator.Create;

  Result := FromPemFile(ClientId, PemPath, Clock, TokenGenerator);
end;

class function TCertificateCredential.FromPemFile(const ClientId, PemPath: string; const Clock: IClock; const TokenGenerator: ITokenGenerator): IClientCredential;
begin
  Result := TCertificateCredential.Create(ClientId, PemPath, Clock, TokenGenerator);
end;

constructor TCertificateCredential.Create(const ClientId, PemPath: string; const Clock: IClock; const TokenGenerator: ITokenGenerator);
begin
  inherited Create;
  FClientId       := ClientId;
  FClock          := Clock;
  FTokenGenerator := TokenGenerator;

  TOpenSsl.EnsureLoaded;
  LoadPem(PemPath);
end;

destructor TCertificateCredential.Destroy;
begin
  if Assigned(FPrivateKey) then
    EVP_PKEY_free(FPrivateKey);
  inherited;
end;

procedure TCertificateCredential.LoadPem(const PemPath: string);
begin
  const PemBytes = ReadPemFile(PemPath);
  const Certificate = ReadCertificate(PemBytes, PemPath);
  try
    FThumbprint := CertificateThumbprint(Certificate);
    FPrivateKey := ReadPrivateKey(PemBytes, PemPath);
    GuardRsaKey(PemPath);
    GuardKeyMatchesCertificate(Certificate, PemPath);
  finally
    X509_free(Certificate);
  end;
end;

function TCertificateCredential.ReadPemFile(const PemPath: string): TBytes;
begin
  const FileFound = TFile.Exists(PemPath);
  if not FileFound then
    raise EUpstreamCredentialInvalid.CreateFmt(PemFileNotFound, [PemPath]);

  try
    Result := TFile.ReadAllBytes(PemPath);
  except
    on EInOutError do
      raise EUpstreamCredentialInvalid.CreateFmt(PemFileUnreadable, [PemPath]);
    on EStreamError do
      raise EUpstreamCredentialInvalid.CreateFmt(PemFileUnreadable, [PemPath]);
  end;
end;

function TCertificateCredential.ReadCertificate(const PemBytes: TBytes; const PemPath: string): PX509;
begin
  const IsEmpty = (Length(PemBytes) = 0);
  if IsEmpty then
    raise EUpstreamCredentialInvalid.CreateFmt(PemCertificateMissing, [PemPath]);

  const Bio = BIO_new_mem_buf(PemBytes[0], Length(PemBytes));
  try
    Result := PEM_read_bio_X509(Bio, nil, nil, nil);
  finally
    BIO_free(Bio);
  end;

  if not Assigned(Result) then
  begin
    ERR_clear_error;
    raise EUpstreamCredentialInvalid.CreateFmt(PemCertificateMissing, [PemPath]);
  end;
end;

function TCertificateCredential.CertificateThumbprint(const Certificate: PX509): string;
begin
  const DerLength = i2d_X509(Certificate, nil);
  var Der: TBytes;
  SetLength(Der, DerLength);
  // i2d_X509 advances the cursor past the bytes it writes.
  var Cursor := PByte(Der);
  i2d_X509(Certificate, @Cursor);

  var Hash := THashSHA2.Create(THashSHA2.TSHA2Version.SHA256);
  Hash.Update(Der);

  const Digest = Hash.HashAsBytes;
  Result := TNetEncoding.Base64URL.EncodeBytesToString(Digest);
end;

function TCertificateCredential.ReadPrivateKey(const PemBytes: TBytes; const PemPath: string): PEVP_PKEY;
begin
  const Bio = BIO_new_mem_buf(PemBytes[0], Length(PemBytes));
  try
    Result := PEM_read_bio_PrivateKey(Bio, nil, nil, @NoPassphrase);
  finally
    BIO_free(Bio);
  end;

  if not Assigned(Result) then
  begin
    ERR_clear_error;
    raise EUpstreamCredentialInvalid.CreateFmt(PemPrivateKeyMissing, [PemPath]);
  end;
end;

procedure TCertificateCredential.GuardRsaKey(const PemPath: string);
begin
  const IsRsaKey = (EVP_PKEY_base_id(FPrivateKey) = EVP_PKEY_RSA);
  if not IsRsaKey then
    raise EUpstreamCredentialInvalid.CreateFmt(PemKeyNotRsa, [PemPath]);
end;

procedure TCertificateCredential.GuardKeyMatchesCertificate(const Certificate: PX509; const PemPath: string);
begin
  const KeyMatches = (X509_check_private_key(Certificate, FPrivateKey) = 1);
  if not KeyMatches then
  begin
    ERR_clear_error;
    raise EUpstreamCredentialInvalid.CreateFmt(PemKeyMismatch, [PemPath]);
  end;
end;

function TCertificateCredential.WithCredential(const TokenUrl: string; const Fields: TArray<TPair<string, string>>): TArray<TPair<string, string>>;
begin
  const Assertion = BuildAssertion(TokenUrl);

  const ClientIdField = TPair<string, string>.Create('client_id', FClientId);
  const AssertionTypeField = TPair<string, string>.Create('client_assertion_type', JwtBearerAssertionType);
  const AssertionField = TPair<string, string>.Create('client_assertion', Assertion);

  Result := Fields + [ClientIdField, AssertionTypeField, AssertionField];
end;

function TCertificateCredential.BuildAssertion(const TokenUrl: string): string;
begin
  const EncodedHeader = EncodePart(HeaderJson);
  const EncodedClaims = EncodePart(ClaimsJson(TokenUrl));
  const SigningInput = Format('%s.%s', [EncodedHeader, EncodedClaims]);

  const Signature = Sign(SigningInput);
  Result := Format('%s.%s', [SigningInput, Signature]);
end;

function TCertificateCredential.HeaderJson: string;
begin
  const Header = TJSONObject.Create;
  try
    Header.AddPair('alg', 'RS256');
    Header.AddPair('typ', 'JWT');
    Header.AddPair('x5t#S256', FThumbprint);

    Result := Header.ToJSON;
  finally
    Header.Free;
  end;
end;

function TCertificateCredential.ClaimsJson(const TokenUrl: string): string;
begin
  const IssuedAt = DateTimeToUnix(FClock.NowUtc, True);
  const ExpiresAt = IssuedAt + AssertionLifetimeSeconds;

  const Claims = TJSONObject.Create;
  try
    Claims.AddPair('aud', TokenUrl);
    Claims.AddPair('iss', FClientId);
    Claims.AddPair('sub', FClientId);
    Claims.AddPair('jti', FTokenGenerator.NewToken);
    Claims.AddPair('nbf', TJSONNumber.Create(IssuedAt));
    Claims.AddPair('iat', TJSONNumber.Create(IssuedAt));
    Claims.AddPair('exp', TJSONNumber.Create(ExpiresAt));

    Result := Claims.ToJSON;
  finally
    Claims.Free;
  end;
end;

function TCertificateCredential.EncodePart(const Json: string): string;
begin
  const JsonBytes = TEncoding.UTF8.GetBytes(Json);

  Result := TNetEncoding.Base64URL.EncodeBytesToString(JsonBytes);
end;

function TCertificateCredential.Sign(const SigningInput: string): string;
begin
  const SignedData = TEncoding.ASCII.GetBytes(SigningInput);
  const SignedLength = TIdC_SIZET(Length(SignedData));

  const Context = EVP_MD_CTX_new;
  CheckSignStep(Assigned(Context));
  try
    const Digest = EVP_sha256;
    const InitResult = EVP_DigestSignInit(Context, nil, Digest, nil, FPrivateKey);
    CheckSignStep(InitResult = 1);

    // A first call without a buffer reports the signature length.
    var SignatureLength: TIdC_SIZET := 0;
    const SizeResult = EVP_DigestSign(Context, nil, @SignatureLength, PByte(SignedData), SignedLength);
    CheckSignStep(SizeResult = 1);

    var Signature: TBytes;
    SetLength(Signature, SignatureLength);
    const SignResult = EVP_DigestSign(Context, PByte(Signature), @SignatureLength, PByte(SignedData), SignedLength);
    CheckSignStep(SignResult = 1);
    SetLength(Signature, SignatureLength);

    Result := TNetEncoding.Base64URL.EncodeBytesToString(Signature);
  finally
    EVP_MD_CTX_free(Context);
  end;
end;

procedure TCertificateCredential.CheckSignStep(const Succeeded: Boolean);
begin
  if not Succeeded then
  begin
    ERR_clear_error;
    raise EUpstreamError.Create(AssertionSigningFailed);
  end;
end;

end.
