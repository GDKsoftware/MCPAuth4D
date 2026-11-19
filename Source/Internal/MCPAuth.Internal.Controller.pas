unit MCPAuth.Internal.Controller;

interface

uses
  System.JSON,
  MCPAuth.Resource.Types,
  MCPAuth.Resource.Interfaces,
  MCPAuth.Resource.ServiceAuth,
  MCPAuth.OAuth.Types,
  MCPAuth.OAuth.Interfaces,
  MCPAuth.Identity.Types,
  MCPAuth.Identity.Interfaces,
  MCPAuth.Web.Types,
  MCPAuth.Web.Router;

type
  // The endpoints MCP servers on the same machine call with their service credentials.
  // Every route needs HTTP Basic service authentication and only ever answers for the authenticated resource.
  // Register does not set a not-found handler, so unknown paths keep the router's JSON 404.
  TInternalController = class
  private type
    TAuthenticatedHandler = reference to function(const Request: TWebRequest; const Resource: TResourceDefinition): TWebResponse;

  private
    FAuthenticator: TServiceAuthenticator;
    FTokens: ITokenRepository;
    FAccounts: ILinkedAccounts;

    class function ReadAuthorization(const Request: TWebRequest): string; static;
    class function WithNoStore(const Response: TWebResponse): TWebResponse; static;
    class function ReplyJson(const StatusCode: Integer; const Body: string): TWebResponse; static;
    class function ReplyError(const StatusCode: Integer; const ErrorCode: string): TWebResponse; static;
    class function InactiveToken: TWebResponse; static;
    class function ToUnixSeconds(const ValueUtc: TDateTime): Int64; static;
    class function TryParseAccountKey(const Value: string; out Key: TAccountKey): Boolean; static;
    class function FindProvider(const Resource: TResourceDefinition; const ProviderName: string; out Provider: TResourceProvider): Boolean; static;
    class function IsServedBy(const Resource: TResourceDefinition; const ProviderName: string): Boolean; static;
    class function ReadStringField(const Body: TJSONObject; const Name: string): string; static;
    class function AccountToJson(const Account: TLinkedAccount): TJSONObject; static;

    function Protect(const Handler: TAuthenticatedHandler): TWebHandler;
    function RunAuthenticated(const Handler: TAuthenticatedHandler; const Request: TWebRequest): TWebResponse;
    function Introspect(const Request: TWebRequest; const Resource: TResourceDefinition): TWebResponse;
    function ListAccounts(const Request: TWebRequest; const Resource: TResourceDefinition): TWebResponse;
    function GetUpstreamToken(const Request: TWebRequest; const Resource: TResourceDefinition): TWebResponse;
    function IntrospectionOf(const Token: TIssuedToken): TWebResponse;
    function IssueUpstreamToken(const UserId: string; const Key: TAccountKey; const Provider: TResourceProvider): TWebResponse;
    function BuildAccountList(const UserId: string; const Resource: TResourceDefinition): TWebResponse;

  public
    constructor Create(const Registry: IResourceRegistry; const Tokens: ITokenRepository; const Accounts: ILinkedAccounts);
    destructor Destroy; override;

    procedure Register(const Router: TWebRouter);
  end;

implementation

uses
  System.SysUtils,
  System.DateUtils,
  MCPAuth.Identity.Exceptions,
  MCPAuth.Upstream.Exceptions,
  MCPAuth.Upstream.Types,
  MCPAuth.Secret.Hash,
  MCPAuth.Web.ErrorLog;

const
  PostMethod = 'POST';
  IntrospectPath = '/internal/introspect';
  AccountsPath = '/internal/accounts';
  UpstreamTokenPath = '/internal/upstream-token';
  AuthorizationHeader = 'Authorization';
  ChallengeHeader = 'WWW-Authenticate';
  ChallengeValue = 'Basic realm="mcpauth"';
  CacheControlHeader = 'Cache-Control';
  NoStore = 'no-store';
  KeySeparator = ':';
  KeyPartCount = 3;
  StatusOk = 200;
  StatusBadRequest = 400;
  StatusUnauthorized = 401;
  StatusForbidden = 403;
  StatusNotFound = 404;
  StatusConflict = 409;
  StatusServerError = 500;
  StatusBadGateway = 502;
  InactiveBody = '{"active":false}';
  BearerTokenType = 'Bearer';
  ReconnectRequiredError = 'reconnect_required';
  SubField = 'sub';
  AccountField = 'account';

{ TInternalController }

constructor TInternalController.Create(const Registry: IResourceRegistry; const Tokens: ITokenRepository; const Accounts: ILinkedAccounts);
begin
  inherited Create;

  FAuthenticator := TServiceAuthenticator.Create(Registry);
  FTokens := Tokens;
  FAccounts := Accounts;
end;

destructor TInternalController.Destroy;
begin
  FAuthenticator.Free;

  inherited;
end;

procedure TInternalController.Register(const Router: TWebRouter);
begin
  Router.Add(PostMethod, IntrospectPath, Protect(Introspect));
  Router.Add(PostMethod, AccountsPath, Protect(ListAccounts));
  Router.Add(PostMethod, UpstreamTokenPath, Protect(GetUpstreamToken));
end;

class function TInternalController.ReadAuthorization(const Request: TWebRequest): string;
begin
  Result := '';
  if not Assigned(Request.Headers) then
    Exit;

  for var Header in Request.Headers do
  begin
    if SameText(Header.Key, AuthorizationHeader) then
      Exit(Header.Value);
  end;
end;

class function TInternalController.WithNoStore(const Response: TWebResponse): TWebResponse;
begin
  Result := Response;
  Result.AddHeader(CacheControlHeader, NoStore);
end;

class function TInternalController.ReplyJson(const StatusCode: Integer; const Body: string): TWebResponse;
begin
  Result := WithNoStore(TWebResponse.Json(StatusCode, Body));
end;

class function TInternalController.ReplyError(const StatusCode: Integer; const ErrorCode: string): TWebResponse;
begin
  Result := WithNoStore(TWebResponse.Error(StatusCode, ErrorCode, ''));
end;

class function TInternalController.InactiveToken: TWebResponse;
begin
  Result := ReplyJson(StatusOk, InactiveBody);
end;

class function TInternalController.ToUnixSeconds(const ValueUtc: TDateTime): Int64;
begin
  Result := DateTimeToUnix(ValueUtc, True);
end;

class function TInternalController.TryParseAccountKey(const Value: string; out Key: TAccountKey): Boolean;
begin
  Key := Default(TAccountKey);

  const Parts = Value.Split([KeySeparator]);
  Result := (Length(Parts) = KeyPartCount);
  if Result then
  begin
    Key.Provider := Parts[0];
    Key.TenantId := Parts[1];
    Key.ObjectId := Parts[2];
  end;
end;

class function TInternalController.FindProvider(const Resource: TResourceDefinition; const ProviderName: string; out Provider: TResourceProvider): Boolean;
begin
  for var Candidate in Resource.Providers do
  begin
    if SameText(Candidate.Provider, ProviderName) then
    begin
      Provider := Candidate;
      Exit(True);
    end;
  end;

  Provider := Default(TResourceProvider);
  Result := False;
end;

class function TInternalController.IsServedBy(const Resource: TResourceDefinition; const ProviderName: string): Boolean;
begin
  var Provider: TResourceProvider;
  Result := FindProvider(Resource, ProviderName, Provider);
end;

class function TInternalController.ReadStringField(const Body: TJSONObject; const Name: string): string;
begin
  var Value: string;
  if Body.TryGetValue<string>(Name, Value) then
    Result := Value
  else
    Result := '';
end;

class function TInternalController.AccountToJson(const Account: TLinkedAccount): TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair('key', Account.Key.Value);
  Result.AddPair('provider', Account.Key.Provider);
  Result.AddPair('display_name', Account.DisplayName);
  Result.AddPair('user_name', Account.UserName);
  Result.AddPair('needs_reconnect', TJSONBool.Create(Account.NeedsReconnect));
end;

function TInternalController.Protect(const Handler: TAuthenticatedHandler): TWebHandler;
begin
  Result :=
    function(const Request: TWebRequest): TWebResponse
    begin
      Result := RunAuthenticated(Handler, Request);
    end;
end;

function TInternalController.RunAuthenticated(const Handler: TAuthenticatedHandler; const Request: TWebRequest): TWebResponse;
begin
  var Resource: TResourceDefinition;
  const IsAuthenticated = FAuthenticator.TryAuthenticate(ReadAuthorization(Request), Resource);
  if not IsAuthenticated then
  begin
    Result := ReplyError(StatusUnauthorized, 'unauthorized');
    Result.AddHeader(ChallengeHeader, ChallengeValue);
    Exit;
  end;

  try
    Result := Handler(Request, Resource);
  except
    on EUpstreamError do
      Result := ReplyError(StatusBadGateway, 'upstream_error');
    on E: Exception do
    begin
      TWebErrorLog.Unexpected(E, Request.Path);
      Result := ReplyError(StatusServerError, 'server_error');
    end;
  end;
end;

function TInternalController.Introspect(const Request: TWebRequest; const Resource: TResourceDefinition): TWebResponse;
begin
  const TokenValue = Request.FormField('token');
  if TokenValue.IsEmpty then
    Exit(InactiveToken);

  var Token: TIssuedToken;
  const IsKnown = FTokens.TryGet(TTokenHash.Of(TokenValue), Token);
  const IsAccessTokenOfCaller = (IsKnown and (Token.Kind = TTokenKind.Access) and (Token.Resource = Resource.ResourceUri));
  if not IsAccessTokenOfCaller then
    Exit(InactiveToken);

  Result := IntrospectionOf(Token);
end;

function TInternalController.IntrospectionOf(const Token: TIssuedToken): TWebResponse;
begin
  const Json = TJSONObject.Create;
  try
    Json.AddPair('active', TJSONBool.Create(True));
    Json.AddPair(SubField, Token.UserId);
    Json.AddPair('scope', Token.Scope);
    Json.AddPair('aud', Token.Resource);
    Json.AddPair('client_id', Token.ClientId);
    Json.AddPair('exp', TJSONNumber.Create(ToUnixSeconds(Token.ExpiresAtUtc)));
    Json.AddPair('token_type', BearerTokenType);

    Result := ReplyJson(StatusOk, Json.ToJSON);
  finally
    Json.Free;
  end;
end;

function TInternalController.ListAccounts(const Request: TWebRequest; const Resource: TResourceDefinition): TWebResponse;
begin
  const Body = Request.JsonBody;
  if not Assigned(Body) then
    Exit(ReplyError(StatusBadRequest, 'invalid_request'));

  try
    const UserId = ReadStringField(Body, SubField);
    if UserId.IsEmpty then
      Exit(ReplyError(StatusBadRequest, 'invalid_request'));

    Result := BuildAccountList(UserId, Resource);
  finally
    Body.Free;
  end;
end;

function TInternalController.BuildAccountList(const UserId: string; const Resource: TResourceDefinition): TWebResponse;
begin
  const List = TJSONArray.Create;
  try
    for var Account in FAccounts.ListForUser(UserId) do
    begin
      if IsServedBy(Resource, Account.Key.Provider) then
        List.AddElement(AccountToJson(Account));
    end;

    Result := ReplyJson(StatusOk, List.ToJSON);
  finally
    List.Free;
  end;
end;

function TInternalController.GetUpstreamToken(const Request: TWebRequest; const Resource: TResourceDefinition): TWebResponse;
begin
  const Body = Request.JsonBody;
  if not Assigned(Body) then
    Exit(ReplyError(StatusBadRequest, 'invalid_request'));

  try
    const UserId = ReadStringField(Body, SubField);
    const AccountValue = ReadStringField(Body, AccountField);
    if UserId.IsEmpty or AccountValue.IsEmpty then
      Exit(ReplyError(StatusBadRequest, 'invalid_request'));

    var Key: TAccountKey;
    if not TryParseAccountKey(AccountValue, Key) then
      Exit(ReplyError(StatusNotFound, 'account_not_found'));

    // Both forbidden cases come before any lookup of the account, so they reveal nothing about it.
    const HasConsent = FTokens.HasActiveFamily(UserId, Resource.ResourceUri);
    var Provider: TResourceProvider;
    const IsProviderOfResource = FindProvider(Resource, Key.Provider, Provider);
    const IsAllowed = (HasConsent and IsProviderOfResource);
    if not IsAllowed then
      Exit(ReplyError(StatusForbidden, 'forbidden'));

    Result := IssueUpstreamToken(UserId, Key, Provider);
  finally
    Body.Free;
  end;
end;

function TInternalController.IssueUpstreamToken(const UserId: string; const Key: TAccountKey; const Provider: TResourceProvider): TWebResponse;
begin
  try
    const Token = FAccounts.GetAccessToken(UserId, Key, Provider.Scopes);

    const Json = TJSONObject.Create;
    try
      Json.AddPair('access_token', Token.AccessToken);
      Json.AddPair('expires_at', TJSONNumber.Create(ToUnixSeconds(Token.ExpiresAtUtc)));
      Result := ReplyJson(StatusOk, Json.ToJSON);
    finally
      Json.Free;
    end;
  except
    on ELinkedAccountNotFound do
      Result := ReplyError(StatusNotFound, 'account_not_found');
    on E: ELinkedAccountNeedsReconnect do
    begin
      const Json = TJSONObject.Create;
      try
        Json.AddPair('error', ReconnectRequiredError);
        Json.AddPair('reason', E.Reason);
        Result := ReplyJson(StatusConflict, Json.ToJSON);
      finally
        Json.Free;
      end;
    end;
  end;
end;

end.
