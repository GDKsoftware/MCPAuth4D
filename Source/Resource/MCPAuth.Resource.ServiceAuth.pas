unit MCPAuth.Resource.ServiceAuth;

interface

uses
  MCPAuth.Resource.Types,
  MCPAuth.Resource.Interfaces;

type
  TServiceAuthenticator = class
  private
    FRegistry: IResourceRegistry;

    function TryDecodeBasicCredentials(const AuthorizationHeader: string; out ServiceId, Secret: string): Boolean;

  public
    constructor Create(const Registry: IResourceRegistry);

    class function HashSecret(const Secret: string): string; static;

    function TryAuthenticate(const AuthorizationHeader: string; out Resource: TResourceDefinition): Boolean;
  end;

implementation

uses
  System.SysUtils,
  System.StrUtils,
  System.NetEncoding,
  MCPAuth.Secret.Hash;

const
  BasicScheme = 'Basic ';
  CredentialSeparator = ':';

{ TServiceAuthenticator }

constructor TServiceAuthenticator.Create(const Registry: IResourceRegistry);
begin
  inherited Create;

  FRegistry := Registry;
end;

class function TServiceAuthenticator.HashSecret(const Secret: string): string;
begin
  Result := TTokenHash.Of(Secret);
end;

function TServiceAuthenticator.TryAuthenticate(const AuthorizationHeader: string; out Resource: TResourceDefinition): Boolean;
begin
  Resource := Default(TResourceDefinition);

  var ServiceId: string;
  var Secret: string;
  const HasCredentials = TryDecodeBasicCredentials(AuthorizationHeader, ServiceId, Secret);
  if not HasCredentials then
    Exit(False);

  var Candidate: TResourceDefinition;
  const IsKnownService = FRegistry.TryGetByServiceId(ServiceId, Candidate);

  // An unknown service is compared against a hash of the same length, so both failures take the same work.
  const ExpectedHash = IfThen(IsKnownService, Candidate.ServiceSecretHash, HashSecret(''));
  const SecretMatches = TTokenHash.SameHash(HashSecret(Secret), ExpectedHash);

  Result := (IsKnownService and SecretMatches);
  if Result then
    Resource := Candidate;
end;

function TServiceAuthenticator.TryDecodeBasicCredentials(const AuthorizationHeader: string; out ServiceId, Secret: string): Boolean;
begin
  ServiceId := '';
  Secret := '';

  const IsBasic = AuthorizationHeader.StartsWith(BasicScheme, True);
  if not IsBasic then
    Exit(False);

  var Credentials: string;
  try
    const Encoded = AuthorizationHeader.Substring(BasicScheme.Length).Trim;
    const Decoded = TNetEncoding.Base64.DecodeStringToBytes(Encoded);
    Credentials := TEncoding.UTF8.GetString(Decoded);
  except
    on EEncodingError do
      Exit(False);
    on EConvertError do
      Exit(False);
  end;

  const SeparatorIndex = Credentials.IndexOf(CredentialSeparator);
  const HasSeparator = (SeparatorIndex >= 0);
  if not HasSeparator then
    Exit(False);

  ServiceId := Credentials.Substring(0, SeparatorIndex);
  Secret := Credentials.Substring(SeparatorIndex + 1);
  Result := (not ServiceId.IsEmpty) and (not Secret.IsEmpty);
end;

end.
