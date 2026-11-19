unit MCPAuth.Secret.KeyRing;

interface

uses
  System.SysUtils,
  Spring.Collections,
  MCPAuth.Secret.Interfaces;

type
  TVariableReader = reference to function(const Name: string): string;

  TKeyRing = class(TInterfacedObject, IKeyRing)
  private
    FCurrentKeyId: string;
    FKeys: IDictionary<string, TBytes>;

    class function ReadEnvironmentVariable(const Name: string): string; static;
    class function ReadMasterKeyId(const Prefix: string; const ReadVariable: TVariableReader): string; static;
    class function ReadMasterKey(const Prefix, KeyId: string; const ReadVariable: TVariableReader): TBytes; static;
    class procedure AddPreviousKeys(const Keys: IDictionary<string, TBytes>; const PreviousKeys: string); static;
    class procedure AddPreviousKey(const Keys: IDictionary<string, TBytes>; const Entry: string); static;
    class function DecodeKey(const KeyId, Encoded: string): TBytes; static;

    procedure AddKey(const KeyId: string; const Key: TBytes);

  public
    class function FromEnvironment(const Prefix: string): IKeyRing; static;
    class function FromVariables(const Prefix: string; const ReadVariable: TVariableReader): IKeyRing; static;

    constructor Create(const CurrentKeyId: string; const Keys: IDictionary<string, TBytes>);

    function TryGetKey(const KeyId: string; out Key: TBytes): Boolean;
    function GetCurrentKeyId: string;
  end;

implementation

uses
  System.NetEncoding;

const
  KeyLength = 32;
  MaxKeyIdLength = 255;
  DefaultKeyId = '1';
  EntrySeparator = ';';
  KeyIdSeparator = '=';
  MasterKeyVariable = '%s_MASTER_KEY';
  MasterKeyIdVariable = '%s_MASTER_KEY_ID';
  PreviousKeysVariable = '%s_PREVIOUS_KEYS';

resourcestring
  VariableNotSet = 'Environment variable %s is not set';
  KeyNotValid = 'Key "%s" must be the base64 encoding of 32 bytes';
  KeyIdNotValid = 'A key id must have 1 to 255 UTF-8 bytes';
  PreviousKeyNotValid = 'Each previous key must have the form id=base64';
  CurrentKeyMissing = 'The key ring has no key for the current key id "%s"';

{ TKeyRing }

class function TKeyRing.FromEnvironment(const Prefix: string): IKeyRing;
begin
  Result := FromVariables(Prefix, ReadEnvironmentVariable);
end;

class function TKeyRing.FromVariables(const Prefix: string; const ReadVariable: TVariableReader): IKeyRing;
begin
  const CurrentKeyId = ReadMasterKeyId(Prefix, ReadVariable);
  const PreviousKeysName = Format(PreviousKeysVariable, [Prefix]);
  const PreviousKeys = ReadVariable(PreviousKeysName);
  const Keys = TCollections.CreateDictionary<string, TBytes>;

  // The master key is added last, so it wins over a previous key with the same id.
  AddPreviousKeys(Keys, PreviousKeys);
  Keys[CurrentKeyId] := ReadMasterKey(Prefix, CurrentKeyId, ReadVariable);

  Result := TKeyRing.Create(CurrentKeyId, Keys);
end;

class function TKeyRing.ReadEnvironmentVariable(const Name: string): string;
begin
  Result := GetEnvironmentVariable(Name);
end;

class function TKeyRing.ReadMasterKeyId(const Prefix: string; const ReadVariable: TVariableReader): string;
begin
  const VariableName = Format(MasterKeyIdVariable, [Prefix]);
  const KeyId = ReadVariable(VariableName);

  Result := KeyId.Trim;
  if Result.IsEmpty then
    Result := DefaultKeyId;
end;

class function TKeyRing.ReadMasterKey(const Prefix, KeyId: string; const ReadVariable: TVariableReader): TBytes;
begin
  const VariableName = Format(MasterKeyVariable, [Prefix]);
  const Value = ReadVariable(VariableName);
  const Encoded = Value.Trim;
  if Encoded.IsEmpty then
    raise ESecretConfigurationError.CreateFmt(VariableNotSet, [VariableName]);

  Result := DecodeKey(KeyId, Encoded);
end;

class procedure TKeyRing.AddPreviousKeys(const Keys: IDictionary<string, TBytes>; const PreviousKeys: string);
begin
  for var Entry in PreviousKeys.Split([EntrySeparator]) do
  begin
    const IsBlank = Entry.Trim.IsEmpty;
    if not IsBlank then
      AddPreviousKey(Keys, Entry);
  end;
end;

class procedure TKeyRing.AddPreviousKey(const Keys: IDictionary<string, TBytes>; const Entry: string);
begin
  const SeparatorIndex = Entry.IndexOf(KeyIdSeparator);
  const HasKeyId = (SeparatorIndex > 0);
  if not HasKeyId then
    raise ESecretConfigurationError.Create(PreviousKeyNotValid);

  const KeyId = Entry.Substring(0, SeparatorIndex).Trim;
  const Encoded = Entry.Substring(SeparatorIndex + 1).Trim;

  Keys[KeyId] := DecodeKey(KeyId, Encoded);
end;

class function TKeyRing.DecodeKey(const KeyId, Encoded: string): TBytes;
begin
  try
    Result := TNetEncoding.Base64String.DecodeStringToBytes(Encoded);
  except
    on EEncodingError do
      raise ESecretConfigurationError.CreateFmt(KeyNotValid, [KeyId]);
  end;
end;

constructor TKeyRing.Create(const CurrentKeyId: string; const Keys: IDictionary<string, TBytes>);
begin
  inherited Create;
  FCurrentKeyId := CurrentKeyId;
  FKeys         := TCollections.CreateDictionary<string, TBytes>;

  for var Pair in Keys do
  begin
    AddKey(Pair.Key, Pair.Value);
  end;

  const HasCurrentKey = FKeys.ContainsKey(CurrentKeyId);
  if not HasCurrentKey then
    raise ESecretConfigurationError.CreateFmt(CurrentKeyMissing, [CurrentKeyId]);
end;

procedure TKeyRing.AddKey(const KeyId: string; const Key: TBytes);
begin
  const KeyIdLength = TEncoding.UTF8.GetByteCount(KeyId);
  const IsValidKeyId = ((KeyIdLength > 0) and (KeyIdLength <= MaxKeyIdLength));
  if not IsValidKeyId then
    raise ESecretConfigurationError.Create(KeyIdNotValid);

  const HasKeyLength = (Length(Key) = KeyLength);
  if not HasKeyLength then
    raise ESecretConfigurationError.CreateFmt(KeyNotValid, [KeyId]);

  FKeys[KeyId] := Copy(Key);
end;

function TKeyRing.TryGetKey(const KeyId: string; out Key: TBytes): Boolean;
begin
  Result := FKeys.TryGetValue(KeyId, Key);
  if Result then
    Key := Copy(Key);
end;

function TKeyRing.GetCurrentKeyId: string;
begin
  Result := FCurrentKeyId;
end;

end.
