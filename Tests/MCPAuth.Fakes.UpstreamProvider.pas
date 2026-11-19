unit MCPAuth.Fakes.UpstreamProvider;

interface

uses
  MCPAuth.Upstream.Types,
  MCPAuth.Upstream.Interfaces;

type
  // Remembers the last authorization request and checks PKCE and the redirect URI on the code exchange, like a real provider.
  TFakeUpstreamProvider = class(TInterfacedObject, IUpstreamProvider)
  private
    FName: string;
    FTenantId: string;
    FObjectId: string;
    FDisplayName: string;
    FUserName: string;
    FRefreshToken: string;
    FScope: string;
    FExpiresAtUtc: TDateTime;
    FLastState: string;
    FLastChallenge: string;
    FLastRedirectUri: string;
    FExchangeCount: Integer;
    FRefreshCount: Integer;

    function BuildTokens: TUpstreamTokens;

  public
    constructor Create(const Name: string);

    function AuthorizationUrl(const State, CodeChallenge, RedirectUri: string): string;
    function ExchangeCode(const Code, CodeVerifier, RedirectUri: string): TUpstreamTokens;
    function Refresh(const RefreshToken: string): TUpstreamTokens;
    function GetName: string;

    procedure SetIdentity(const TenantId, ObjectId, DisplayName, UserName: string);

    property RefreshToken: string read FRefreshToken write FRefreshToken;
    property Scope: string read FScope write FScope;
    property ExpiresAtUtc: TDateTime read FExpiresAtUtc write FExpiresAtUtc;
    property LastState: string read FLastState;
    property LastRedirectUri: string read FLastRedirectUri;
    property ExchangeCount: Integer read FExchangeCount;
    property RefreshCount: Integer read FRefreshCount;
  end;

implementation

uses
  System.SysUtils,
  System.NetEncoding,
  MCPAuth.OAuth.Pkce,
  MCPAuth.Upstream.Exceptions;

{ TFakeUpstreamProvider }

constructor TFakeUpstreamProvider.Create(const Name: string);
begin
  inherited Create;

  FName := Name;
  FRefreshToken := 'upstream-refresh';
  FScope := 'openid offline_access';
  SetIdentity('tenant-1', 'object-1', 'Test User', 'user@example.test');
end;

function TFakeUpstreamProvider.AuthorizationUrl(const State, CodeChallenge, RedirectUri: string): string;
begin
  FLastState := State;
  FLastChallenge := CodeChallenge;
  FLastRedirectUri := RedirectUri;

  const EncodedState = TNetEncoding.URL.EncodeForm(State);
  Result := Format('https://login.example.test/authorize?state=%s', [EncodedState]);
end;

function TFakeUpstreamProvider.ExchangeCode(const Code, CodeVerifier, RedirectUri: string): TUpstreamTokens;
begin
  const IsVerifierValid = TPkce.Verify(CodeVerifier, FLastChallenge);
  const IsSameRedirect = (RedirectUri = FLastRedirectUri);
  if not (IsVerifierValid and IsSameRedirect) then
    raise EUpstreamGrantRevoked.Create('The fake provider rejected the code exchange');

  Inc(FExchangeCount);
  Result := BuildTokens;
end;

function TFakeUpstreamProvider.Refresh(const RefreshToken: string): TUpstreamTokens;
begin
  Inc(FRefreshCount);
  Result := BuildTokens;
end;

function TFakeUpstreamProvider.GetName: string;
begin
  Result := FName;
end;

procedure TFakeUpstreamProvider.SetIdentity(const TenantId, ObjectId, DisplayName, UserName: string);
begin
  FTenantId := TenantId;
  FObjectId := ObjectId;
  FDisplayName := DisplayName;
  FUserName := UserName;
end;

function TFakeUpstreamProvider.BuildTokens: TUpstreamTokens;
begin
  Result := Default(TUpstreamTokens);
  Result.AccessToken := Format('upstream-access-%d', [FExchangeCount + FRefreshCount]);
  Result.RefreshToken := FRefreshToken;
  Result.Scope := FScope;
  Result.ExpiresAtUtc := FExpiresAtUtc;
  Result.Identity.Key.Provider := FName;
  Result.Identity.Key.TenantId := FTenantId;
  Result.Identity.Key.ObjectId := FObjectId;
  Result.Identity.DisplayName := FDisplayName;
  Result.Identity.UserName := FUserName;
end;

end.
