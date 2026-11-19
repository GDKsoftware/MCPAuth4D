unit MCPAuth.Upstream.OAuth;

interface

uses
  System.JSON,
  Spring.Collections,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Upstream.Types,
  MCPAuth.Upstream.Interfaces,
  MCPAuth.Upstream.Http.Interfaces;

type
  // An OAuth 2.0 authorization code flow with PKCE against one upstream identity
  // provider. The identity comes from the id_token of the code exchange; a
  // descendant overrides MapIdentity for provider-specific claims.
  TOAuthUpstreamProvider = class(TInterfacedObject, IUpstreamProvider)
  private
    FSettings: TOAuthUpstreamSettings;
    FCredential: IClientCredential;
    FHttp: IUpstreamHttp;
    FClock: IClock;

    function AuthorizationParameters(const State, CodeChallenge, RedirectUri: string): TArray<TPair<string, string>>;
    function ScopeText: string;
    function RequestTokens(const Fields: TArray<TPair<string, string>>; const IncludesIdentity: Boolean): TUpstreamTokens;
    procedure GuardSuccess(const Response: TUpstreamHttpResponse);
    function ErrorCode(const Body: string): string;
    function IsSafeErrorCode(const Code: string): Boolean;
    function ParseTokenResponse(const Body: string; const IncludesIdentity: Boolean): TUpstreamTokens;
    function ParseObject(const Body: string): TJSONObject;
    function ExpiresAtUtc(const Response: TJSONObject): TDateTime;
    function IdentityFromIdToken(const Response: TJSONObject): TUpstreamIdentity;

  protected
    function MapIdentity(const Claims: TJSONObject): TUpstreamIdentity; virtual;
    function RequiredClaim(const Claims: TJSONObject; const Name: string): string;
    function OptionalClaim(const Claims: TJSONObject; const Name: string): string;

  public
    constructor Create(const Settings: TOAuthUpstreamSettings; const Credential: IClientCredential; const Http: IUpstreamHttp; const Clock: IClock);

    function GetName: string;
    function AuthorizationUrl(const State, CodeChallenge, RedirectUri: string): string;
    function ExchangeCode(const Code, CodeVerifier, RedirectUri: string): TUpstreamTokens;
    function Refresh(const RefreshToken: string): TUpstreamTokens;
  end;

implementation

uses
  System.SysUtils,
  System.DateUtils,
  MCPAuth.Upstream.Jwt,
  MCPAuth.Upstream.FormEncoding,
  MCPAuth.Upstream.Exceptions;

const
  HttpOk = 200;
  HttpBadRequest = 400;
  InvalidGrant = 'invalid_grant';
  DefaultLifetimeSeconds = 3600;
  MaxErrorCodeLength = 64;
  SafeErrorCodeCharacters = ['a'..'z', '_'];

resourcestring
  GrantRevoked = 'The %s grant is revoked or expired; the account must be connected again';
  TokenEndpointFailed = 'The %s token endpoint returned HTTP %d (%s)';
  UnrecognizedError = 'unrecognized error';
  TokenResponseUnreadable = 'The %s token endpoint returned a response that is not a JSON object';
  TokenResponseIncomplete = 'The %s token response has no %s';
  IdTokenClaimMissing = 'The %s id_token has no %s claim';

{ TOAuthUpstreamProvider }

constructor TOAuthUpstreamProvider.Create(const Settings: TOAuthUpstreamSettings; const Credential: IClientCredential; const Http: IUpstreamHttp; const Clock: IClock);
begin
  inherited Create;
  FSettings   := Settings;
  FCredential := Credential;
  FHttp       := Http;
  FClock      := Clock;
end;

function TOAuthUpstreamProvider.GetName: string;
begin
  Result := FSettings.Name;
end;

function TOAuthUpstreamProvider.AuthorizationUrl(const State, CodeChallenge, RedirectUri: string): string;
begin
  const Parameters = AuthorizationParameters(State, CodeChallenge, RedirectUri);
  const Query = TFormEncoding.Encode(Parameters);

  Result := Format('%s?%s', [FSettings.AuthorizeUrl, Query]);
end;

function TOAuthUpstreamProvider.AuthorizationParameters(const State, CodeChallenge, RedirectUri: string): TArray<TPair<string, string>>;
begin
  Result := [
    TPair<string, string>.Create('client_id', FSettings.ClientId),
    TPair<string, string>.Create('response_type', 'code'),
    TPair<string, string>.Create('redirect_uri', RedirectUri),
    TPair<string, string>.Create('response_mode', 'query'),
    TPair<string, string>.Create('scope', ScopeText),
    TPair<string, string>.Create('state', State),
    TPair<string, string>.Create('code_challenge', CodeChallenge),
    TPair<string, string>.Create('code_challenge_method', 'S256')
  ];

  Result := Result + FSettings.ExtraAuthorizeParameters;
end;

function TOAuthUpstreamProvider.ScopeText: string;
begin
  Result := string.Join(' ', FSettings.Scopes);
end;

function TOAuthUpstreamProvider.ExchangeCode(const Code, CodeVerifier, RedirectUri: string): TUpstreamTokens;
begin
  const Fields: TArray<TPair<string, string>> = [
    TPair<string, string>.Create('grant_type', 'authorization_code'),
    TPair<string, string>.Create('code', Code),
    TPair<string, string>.Create('redirect_uri', RedirectUri),
    TPair<string, string>.Create('code_verifier', CodeVerifier),
    TPair<string, string>.Create('scope', ScopeText)
  ];

  Result := RequestTokens(Fields, True);
end;

function TOAuthUpstreamProvider.Refresh(const RefreshToken: string): TUpstreamTokens;
begin
  const Fields: TArray<TPair<string, string>> = [
    TPair<string, string>.Create('grant_type', 'refresh_token'),
    TPair<string, string>.Create('refresh_token', RefreshToken),
    TPair<string, string>.Create('scope', ScopeText)
  ];

  Result := RequestTokens(Fields, False);
end;

function TOAuthUpstreamProvider.RequestTokens(const Fields: TArray<TPair<string, string>>; const IncludesIdentity: Boolean): TUpstreamTokens;
begin
  const AuthenticatedFields = FCredential.WithCredential(FSettings.TokenUrl, Fields);

  const Response = FHttp.PostForm(FSettings.TokenUrl, AuthenticatedFields);
  GuardSuccess(Response);

  Result := ParseTokenResponse(Response.Body, IncludesIdentity);
end;

procedure TOAuthUpstreamProvider.GuardSuccess(const Response: TUpstreamHttpResponse);
begin
  const IsSuccess = (Response.StatusCode = HttpOk);
  if IsSuccess then
    Exit;

  // Only the error code is reported: the body may echo tokens or codes.
  var Code := ErrorCode(Response.Body);
  const IsRevoked = ((Response.StatusCode = HttpBadRequest) and (Code = InvalidGrant));
  if IsRevoked then
    raise EUpstreamGrantRevoked.CreateFmt(GrantRevoked, [FSettings.Name]);

  if not IsSafeErrorCode(Code) then
    Code := UnrecognizedError;
  raise EUpstreamError.CreateFmt(TokenEndpointFailed, [FSettings.Name, Response.StatusCode, Code]);
end;

function TOAuthUpstreamProvider.ErrorCode(const Body: string): string;
begin
  Result := '';

  const Value = TJSONObject.ParseJSONValue(Body);
  try
    const IsObject = (Value is TJSONObject);
    if IsObject then
      TJSONObject(Value).TryGetValue<string>('error', Result);
  finally
    Value.Free;
  end;
end;

function TOAuthUpstreamProvider.IsSafeErrorCode(const Code: string): Boolean;
begin
  const HasValidLength = ((Code.Length > 0) and (Code.Length <= MaxErrorCodeLength));
  if not HasValidLength then
    Exit(False);

  for var Character in Code do
  begin
    const IsSafeCharacter = CharInSet(Character, SafeErrorCodeCharacters);
    if not IsSafeCharacter then
      Exit(False);
  end;

  Result := True;
end;

function TOAuthUpstreamProvider.ParseTokenResponse(const Body: string; const IncludesIdentity: Boolean): TUpstreamTokens;
begin
  const Response = ParseObject(Body);
  try
    const HasAccessToken = Response.TryGetValue<string>('access_token', Result.AccessToken);
    if not HasAccessToken then
      raise EUpstreamError.CreateFmt(TokenResponseIncomplete, [FSettings.Name, 'access_token']);

    // A refresh response without refresh_token means the old one stays valid.
    Result.RefreshToken := '';
    Response.TryGetValue<string>('refresh_token', Result.RefreshToken);

    // RFC 6749 5.1: an omitted scope equals the requested scope.
    const HasScope = Response.TryGetValue<string>('scope', Result.Scope);
    if not HasScope then
      Result.Scope := ScopeText;

    Result.ExpiresAtUtc := ExpiresAtUtc(Response);
    Result.Identity     := Default(TUpstreamIdentity);
    if IncludesIdentity then
      Result.Identity := IdentityFromIdToken(Response);
  finally
    Response.Free;
  end;
end;

function TOAuthUpstreamProvider.ParseObject(const Body: string): TJSONObject;
begin
  const Value = TJSONObject.ParseJSONValue(Body);

  const IsObject = (Value is TJSONObject);
  if not IsObject then
  begin
    Value.Free;
    raise EUpstreamError.CreateFmt(TokenResponseUnreadable, [FSettings.Name]);
  end;

  Result := TJSONObject(Value);
end;

function TOAuthUpstreamProvider.ExpiresAtUtc(const Response: TJSONObject): TDateTime;
begin
  var LifetimeSeconds: Int64;
  const HasLifetime = Response.TryGetValue<Int64>('expires_in', LifetimeSeconds);
  if not HasLifetime then
    LifetimeSeconds := DefaultLifetimeSeconds;

  Result := IncSecond(FClock.NowUtc, LifetimeSeconds);
end;

function TOAuthUpstreamProvider.IdentityFromIdToken(const Response: TJSONObject): TUpstreamIdentity;
begin
  var IdToken: string;
  const HasIdToken = Response.TryGetValue<string>('id_token', IdToken);
  if not HasIdToken then
    raise EUpstreamError.CreateFmt(TokenResponseIncomplete, [FSettings.Name, 'id_token']);

  const Claims = TJwtPayload.Decode(IdToken);
  try
    Result := MapIdentity(Claims);
  finally
    Claims.Free;
  end;
end;

function TOAuthUpstreamProvider.MapIdentity(const Claims: TJSONObject): TUpstreamIdentity;
begin
  Result.Key.Provider := FSettings.Name;
  Result.Key.TenantId := '';
  Result.Key.ObjectId := RequiredClaim(Claims, 'sub');
  Result.DisplayName  := OptionalClaim(Claims, 'name');
  Result.UserName     := OptionalClaim(Claims, 'preferred_username');
end;

function TOAuthUpstreamProvider.RequiredClaim(const Claims: TJSONObject; const Name: string): string;
begin
  const HasClaim = (Claims.TryGetValue<string>(Name, Result) and not Result.IsEmpty);
  if not HasClaim then
    raise EUpstreamError.CreateFmt(IdTokenClaimMissing, [FSettings.Name, Name]);
end;

function TOAuthUpstreamProvider.OptionalClaim(const Claims: TJSONObject; const Name: string): string;
begin
  Result := '';
  Claims.TryGetValue<string>(Name, Result);
end;

end.
