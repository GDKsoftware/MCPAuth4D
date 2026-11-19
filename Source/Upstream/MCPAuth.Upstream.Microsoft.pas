unit MCPAuth.Upstream.Microsoft;

interface

uses
  System.JSON,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Upstream.Types,
  MCPAuth.Upstream.Interfaces,
  MCPAuth.Upstream.Http.Interfaces,
  MCPAuth.Upstream.OAuth;

type
  // Microsoft Entra ID, multi-tenant: work and school accounts of any tenant.
  TMicrosoftUpstreamProvider = class(TOAuthUpstreamProvider)
  private
    class function MicrosoftSettings(const ClientId: string; const Scopes: TArray<string>): TOAuthUpstreamSettings; static;
    class function MergeScopes(const Scopes: TArray<string>): TArray<string>; static;
    class function ContainsScope(const Scopes: TArray<string>; const Scope: string): Boolean; static;

  protected
    function MapIdentity(const Claims: TJSONObject): TUpstreamIdentity; override;

  public
    constructor Create(const ClientId: string; const Credential: IClientCredential; const Scopes: TArray<string>; const Http: IUpstreamHttp); overload;
    constructor Create(const ClientId: string; const Credential: IClientCredential; const Scopes: TArray<string>; const Http: IUpstreamHttp; const Clock: IClock); overload;
  end;

implementation

uses
  System.SysUtils,
  Spring.Collections,
  MCPAuth.Clock;

const
  MicrosoftProviderName = 'microsoft';
  MicrosoftAuthorizeUrl = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize';
  MicrosoftTokenUrl = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token';
  SignInScopes: array[0..2] of string = ('openid', 'profile', 'offline_access');

{ TMicrosoftUpstreamProvider }

class function TMicrosoftUpstreamProvider.MicrosoftSettings(const ClientId: string; const Scopes: TArray<string>): TOAuthUpstreamSettings;
begin
  Result.Name         := MicrosoftProviderName;
  Result.AuthorizeUrl := MicrosoftAuthorizeUrl;
  Result.TokenUrl     := MicrosoftTokenUrl;
  Result.ClientId     := ClientId;
  Result.Scopes       := MergeScopes(Scopes);

  Result.ExtraAuthorizeParameters := [TPair<string, string>.Create('prompt', 'select_account')];
end;

class function TMicrosoftUpstreamProvider.MergeScopes(const Scopes: TArray<string>): TArray<string>;
begin
  Result := [];
  for var Scope in SignInScopes do
  begin
    Result := Result + [Scope];
  end;

  for var Scope in Scopes do
  begin
    const TrimmedScope = Scope.Trim;
    const IsNewScope = (not TrimmedScope.IsEmpty and not ContainsScope(Result, TrimmedScope));
    if IsNewScope then
      Result := Result + [TrimmedScope];
  end;
end;

class function TMicrosoftUpstreamProvider.ContainsScope(const Scopes: TArray<string>; const Scope: string): Boolean;
begin
  for var Existing in Scopes do
  begin
    if SameText(Existing, Scope) then
      Exit(True);
  end;

  Result := False;
end;

constructor TMicrosoftUpstreamProvider.Create(const ClientId: string; const Credential: IClientCredential; const Scopes: TArray<string>; const Http: IUpstreamHttp);
begin
  const Clock: IClock = TSystemClock.Create;

  Create(ClientId, Credential, Scopes, Http, Clock);
end;

constructor TMicrosoftUpstreamProvider.Create(const ClientId: string; const Credential: IClientCredential; const Scopes: TArray<string>; const Http: IUpstreamHttp; const Clock: IClock);
begin
  const Settings = MicrosoftSettings(ClientId, Scopes);

  inherited Create(Settings, Credential, Http, Clock);
end;

function TMicrosoftUpstreamProvider.MapIdentity(const Claims: TJSONObject): TUpstreamIdentity;
begin
  Result.Key.Provider := MicrosoftProviderName;
  Result.Key.TenantId := RequiredClaim(Claims, 'tid');
  Result.Key.ObjectId := RequiredClaim(Claims, 'oid');
  Result.DisplayName  := OptionalClaim(Claims, 'name');
  Result.UserName     := OptionalClaim(Claims, 'preferred_username');
end;

end.
