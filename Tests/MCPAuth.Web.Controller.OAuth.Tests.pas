unit MCPAuth.Web.Controller.OAuth.Tests;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  MCPAuth.Fakes.Clock,
  MCPAuth.Fakes.UpstreamProvider,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Store.Interfaces,
  MCPAuth.Upstream.Interfaces,
  MCPAuth.OAuth.Settings,
  MCPAuth.Web.Types,
  MCPAuth.Web.Router,
  MCPAuth.Web.Session.Interfaces,
  MCPAuth.Web.Controller.OAuth;

type
  [TestFixture]
  TOAuthControllerTests = class
  private
    FClock: TFakeClock;
    FClockReference: IClock;
    FStores: TStoreSet;
    FProvider: TFakeUpstreamProvider;
    FProviderReference: IUpstreamProvider;
    FSettings: TMCPAuthSettings;
    FSessions: IWebSessions;
    FController: TOAuthController;
    FRouter: TWebRouter;
    FVerifier: string;

    class function QueryParam(const Url, Name: string): string; static;
    class function CookieValue(const SetCookie: string): string; static;
    class function SetCookieNamed(const Response: TWebResponse; const Name: string): string; static;
    class function HeaderValue(const Response: TWebResponse; const Name: string): string; static;
    class function FindLibraryTemplatesPath: string; static;

    function BuildResourceRegistryJson: string;
    procedure RegisterClient;
    function NewRequest(const Method, Path, Query, Body, SessionCookie: string): TWebRequest;
    function CallbackRequest(const LoginCookie, SessionCookie: string): TWebRequest;
    function StartAuthorizeLogin: string;
    function AuthorizeQuery(const RedirectUri, ChallengeMethod: string): string;
    function SignIn(out PendingId: string): string;
    function CsrfOf(const SessionCookie: string): string;
    function ConsentBody(const PendingId, Csrf, Decision: string): string;
    function IsPendingKnown(const PendingId: string): Boolean;
    function ObtainCode: string;
    function TokenBody(const Code: string): string;

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure MetadataEndpointReturnsJson;

    [Test]
    procedure RegisterEndpointReturns201WithClientId;

    [Test]
    procedure RegisterEndpointRejectsInvalidMetadataAsJson;

    [Test]
    procedure AuthorizeWithoutSessionRedirectsToUpstream;

    [Test]
    procedure AuthorizeWithSessionRedirectsToConsent;

    [Test]
    procedure AuthorizeErrorAfterRedirectValidationRedirectsWithErrorAndState;

    [Test]
    procedure CallbackStartsSessionAndShowsConsentWithResourceName;

    [Test]
    procedure CallbackWithUnknownStateShowsErrorPage;

    [Test]
    procedure CallbackWithoutLoginCookieIsRejected;

    [Test]
    procedure CallbackWithOtherBrowsersLoginCookieIsRejected;

    [Test]
    procedure LoginCookieIsHttpOnlySecureLaxAndClearedAfterSignIn;

    [Test]
    procedure ConsentApproveRedirectsToClientWithCodeAndState;

    [Test]
    procedure ConsentDenyRedirectsToClientWithAccessDenied;

    [Test]
    procedure ConsentPostWithoutCsrfIsRejected;

    [Test]
    procedure ConsentPostWithOtherUsersSessionIsRejected;

    [Test]
    procedure ConsentWithoutSessionIsRejected;

    [Test]
    procedure ConsentPageCannotBeFramed;

    [Test]
    procedure UnregisteredRedirectShowsErrorPageWithoutRedirect;

    [Test]
    procedure UnknownClientShowsErrorPageWithoutRedirect;

    [Test]
    procedure TokenEndpointIssuesTokensAsJsonWithNoStore;

    [Test]
    procedure TokenEndpointErrorsAreJsonWithNoStore;

    [Test]
    procedure TokenEndpointRequiresClientId;

    [Test]
    procedure RevokeEndpointRevokesTheFamily;

    [Test]
    procedure SessionCookieIsHttpOnlySecureLax;

    [Test]
    procedure SessionStoreHoldsOnlyTheHash;

    [Test]
    procedure UnknownPathRenders404Page;

    [Test]
    procedure FirstRegisteredRouteWins;

    [Test]
    procedure UnknownRouteOnRouterWithoutPagesIsJson404;

    [Test]
    procedure FormFieldDecodesPlusAndUtf8;
  end;

implementation

uses
  System.JSON,
  System.IOUtils,
  System.DateUtils,
  System.NetEncoding,
  Spring.Collections,
  MCPAuth.Secret.Hash,
  MCPAuth.Secret.Token,
  MCPAuth.Secret.KeyRing,
  MCPAuth.Secret.AesGcm,
  MCPAuth.Store.Memory,
  MCPAuth.Identity.Interfaces,
  MCPAuth.Identity.Accounts,
  MCPAuth.Identity.Access.AllowAll,
  MCPAuth.Resource.Registry.Json,
  MCPAuth.Upstream.Providers,
  MCPAuth.OAuth.Types,
  MCPAuth.OAuth.Interfaces,
  MCPAuth.OAuth.Pkce,
  MCPAuth.OAuth.Server,
  MCPAuth.Web.Session,
  MCPAuth.Web.Page.WebStencils;

const
  Issuer = 'https://auth.example.test';
  ProviderName = 'fake';
  ClientId = 'client-1';
  RedirectUri = 'http://localhost:9000/callback';
  UnregisteredRedirectUri = 'http://evil.example.test/callback';
  ClientState = 'client state/1';
  ResourceA = 'https://a.example.test/mcp';
  UpstreamCode = 'upstream-code';
  OtherUser = 'user-other';
  KeyId = 'k1';
  KeyLength = 32;
  SessionCookieName = '__Host-mcpauth_session';
  LoginCookieName = '__Host-mcpauth_login';
  FormContentType = 'application/x-www-form-urlencoded';
  StatusOk = 200;
  StatusCreated = 201;
  StatusFound = 302;
  StatusBadRequest = 400;
  StatusForbidden = 403;
  StatusNotFound = 404;

{ TOAuthControllerTests }

class function TOAuthControllerTests.QueryParam(const Url, Name: string): string;
begin
  const QueryStart = Url.IndexOf('?');
  const Query = Url.Substring(QueryStart + 1);
  const Prefix = Format('%s=', [Name]);
  for var Field in Query.Split(['&']) do
  begin
    if Field.StartsWith(Prefix) then
    begin
      const EncodedValue = Field.Substring(Prefix.Length).Replace('+', ' ');
      Exit(TNetEncoding.URL.Decode(EncodedValue));
    end;
  end;

  Result := '';
end;

class function TOAuthControllerTests.CookieValue(const SetCookie: string): string;
begin
  const Pair = SetCookie.Split([';'])[0];
  const SeparatorIndex = Pair.IndexOf('=');

  Result := Pair.Substring(SeparatorIndex + 1);
end;

class function TOAuthControllerTests.SetCookieNamed(const Response: TWebResponse; const Name: string): string;
begin
  for var SetCookie in Response.SetCookies do
  begin
    if SetCookie.StartsWith(Name + '=') then
      Exit(SetCookie);
  end;

  Result := '';
end;

class function TOAuthControllerTests.HeaderValue(const Response: TWebResponse; const Name: string): string;
begin
  for var Header in Response.ExtraHeaders do
  begin
    if SameText(Header.Key, Name) then
      Exit(Header.Value);
  end;

  Result := '';
end;

class function TOAuthControllerTests.FindLibraryTemplatesPath: string;
begin
  var Folder := TPath.GetDirectoryName(ParamStr(0));
  while not Folder.IsEmpty do
  begin
    const Candidate = TPath.Combine(Folder, 'templates');
    const HasDefaultLayout = TFile.Exists(TPath.Combine(Candidate, 'layout.html'));
    if HasDefaultLayout then
      Exit(Candidate);

    Folder := TPath.GetDirectoryName(Folder);
  end;

  raise Exception.Create('The templates folder of the repository was not found');
end;

procedure TOAuthControllerTests.Setup;
begin
  FClock := TFakeClock.Create(EncodeDateTime(2026, 1, 2, 3, 4, 5, 0));
  FClockReference := FClock;
  FStores := TMemoryStore.CreateSet(FClockReference);
  FProvider := TFakeUpstreamProvider.Create(ProviderName);
  FProviderReference := FProvider;
  FSettings := TMCPAuthSettings.Defaults(Issuer);
  FVerifier := TPkce.NewVerifier;

  var Key: TBytes;
  SetLength(Key, KeyLength);
  FillChar(Key[0], KeyLength, 5);
  const Keys = TCollections.CreateDictionary<string, TBytes>;
  Keys[KeyId] := Key;
  const Protector = TAesGcmProtector.Create(TKeyRing.Create(KeyId, Keys));

  const Tokens = TTokenGenerator.Create;
  const Providers = TUpstreamProviders.Create([FProviderReference]);
  const Accounts: ILinkedAccounts = TLinkedAccounts.Create(FStores.Users, FStores.LinkedAccounts, Protector, TAllowAllAccessPolicy.Create, Providers, FClockReference);
  const Registry = TJsonResourceRegistry.FromJson(BuildResourceRegistryJson);
  const Server: IAuthorizationServer = TAuthorizationServer.Create(FStores, Registry, Providers, Accounts, Tokens, FSettings, FClockReference);
  const Pages = TWebStencilsPageRenderer.Create('', FindLibraryTemplatesPath);

  FSessions := TWebSessions.Create(FStores.Sessions, Tokens, FSettings, FClockReference);
  FController := TOAuthController.Create(Server, FStores.Clients, FSessions, Pages, Tokens, FSettings, FClockReference);
  FRouter := TWebRouter.Create;
  FController.Register(FRouter);

  RegisterClient;
end;

procedure TOAuthControllerTests.TearDown;
begin
  FRouter.Free;
  FController.Free;
  FSessions := nil;
  FProviderReference := nil;
  FStores := Default(TStoreSet);
  FClockReference := nil;
end;

function TOAuthControllerTests.BuildResourceRegistryJson: string;
begin
  const Hash = TTokenHash.Of('service-secret');
  const Entry = '{"resource":"%s","name":"%s","service_id":"%s","service_secret_sha256":"%s",' +
                '"providers":[{"provider":"fake","scopes":["read"]}]}';

  Result := Format('{"resources":[%s]}', [Format(Entry, [ResourceA, 'Resource A', 'service-a', Hash])]);
end;

procedure TOAuthControllerTests.RegisterClient;
begin
  var Client := Default(TOAuthClient);
  Client.ClientId     := ClientId;
  Client.ClientName   := 'Test Client';
  Client.RedirectUris := [RedirectUri];
  Client.CreatedAtUtc := FClock.NowUtc;
  FStores.Clients.Save(Client);
end;

function TOAuthControllerTests.NewRequest(const Method, Path, Query, Body, SessionCookie: string): TWebRequest;
begin
  Result := Default(TWebRequest);
  Result.Method        := Method;
  Result.Path          := Path;
  Result.Query         := Query;
  Result.Body          := Body;
  Result.ContentType   := FormContentType;
  Result.RemoteAddress := '127.0.0.1';
  Result.Headers       := TCollections.CreateDictionary<string, string>;
  Result.Cookies       := TCollections.CreateDictionary<string, string>;

  if not SessionCookie.IsEmpty then
    Result.Cookies[SessionCookieName] := SessionCookie;
end;

function TOAuthControllerTests.CallbackRequest(const LoginCookie, SessionCookie: string): TWebRequest;
begin
  const CallbackQuery = Format('code=%s&state=%s', [UpstreamCode, TNetEncoding.URL.EncodeForm(FProvider.LastState)]);

  Result := NewRequest('GET', '/callback/' + ProviderName, CallbackQuery, '', SessionCookie);
  if not LoginCookie.IsEmpty then
    Result.Cookies[LoginCookieName] := LoginCookie;
end;

function TOAuthControllerTests.StartAuthorizeLogin: string;
begin
  const Authorize = FRouter.Dispatch(NewRequest('GET', '/authorize', AuthorizeQuery(RedirectUri, 'S256'), '', ''));

  Result := CookieValue(SetCookieNamed(Authorize, LoginCookieName));
end;

function TOAuthControllerTests.AuthorizeQuery(const RedirectUri, ChallengeMethod: string): string;
begin
  const Fields: TArray<string> = [
    'response_type=code',
    'client_id=' + TNetEncoding.URL.EncodeForm(ClientId),
    'redirect_uri=' + TNetEncoding.URL.EncodeForm(RedirectUri),
    'code_challenge=' + TPkce.ChallengeOf(FVerifier),
    'code_challenge_method=' + ChallengeMethod,
    'state=' + TNetEncoding.URL.EncodeForm(ClientState),
    'scope=mcp',
    'resource=' + TNetEncoding.URL.EncodeForm(ResourceA)
  ];

  Result := string.Join('&', Fields);
end;

function TOAuthControllerTests.SignIn(out PendingId: string): string;
begin
  const LoginCookie = StartAuthorizeLogin;
  const Callback = FRouter.Dispatch(CallbackRequest(LoginCookie, ''));

  Assert.AreEqual(StatusFound, Callback.StatusCode, Callback.Body);

  PendingId := QueryParam(Callback.Location, 'pending');
  Result := CookieValue(SetCookieNamed(Callback, SessionCookieName));
end;

function TOAuthControllerTests.CsrfOf(const SessionCookie: string): string;
begin
  var Session: TWebSession;
  Assert.IsTrue(FStores.Sessions.TryGet(TTokenHash.Of(SessionCookie), Session), 'session stored by hash');

  Result := Session.CsrfToken;
end;

function TOAuthControllerTests.ConsentBody(const PendingId, Csrf, Decision: string): string;
begin
  Result := Format('pending=%s&csrf=%s&decision=%s', [TNetEncoding.URL.EncodeForm(PendingId),
                                                     TNetEncoding.URL.EncodeForm(Csrf),
                                                     Decision]);
end;

function TOAuthControllerTests.IsPendingKnown(const PendingId: string): Boolean;
begin
  var Pending: TPendingAuthorization;
  Result := FStores.Pending.TryGet(PendingId, Pending);
end;

function TOAuthControllerTests.ObtainCode: string;
begin
  var PendingId: string;
  const SessionCookie = SignIn(PendingId);
  const Body = ConsentBody(PendingId, CsrfOf(SessionCookie), 'approve');

  const Response = FRouter.Dispatch(NewRequest('POST', '/consent', '', Body, SessionCookie));

  Result := QueryParam(Response.Location, 'code');
end;

function TOAuthControllerTests.TokenBody(const Code: string): string;
begin
  Result := Format('grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s',
                   [TNetEncoding.URL.EncodeForm(Code),
                    TNetEncoding.URL.EncodeForm(RedirectUri),
                    ClientId,
                    FVerifier]);
end;

procedure TOAuthControllerTests.MetadataEndpointReturnsJson;
begin
  const Response = FRouter.Dispatch(NewRequest('GET', '/.well-known/oauth-authorization-server', '', '', ''));

  Assert.AreEqual(StatusOk, Response.StatusCode);
  Assert.StartsWith('application/json', Response.ContentType);

  const Metadata = TJSONObject.ParseJSONValue(Response.Body) as TJSONObject;
  try
    Assert.AreEqual(Issuer, Metadata.GetValue<string>('issuer'));
    Assert.AreEqual(Issuer + '/token', Metadata.GetValue<string>('token_endpoint'));
  finally
    Metadata.Free;
  end;
end;

procedure TOAuthControllerTests.RegisterEndpointReturns201WithClientId;
begin
  var Request := NewRequest('POST', '/register', '', '{"redirect_uris":["http://localhost:7000/cb"],"client_name":"New"}', '');
  Request.ContentType := 'application/json';

  const Response = FRouter.Dispatch(Request);

  Assert.AreEqual(StatusCreated, Response.StatusCode, Response.Body);
  Assert.StartsWith('application/json', Response.ContentType);

  const Registered = TJSONObject.ParseJSONValue(Response.Body) as TJSONObject;
  try
    const NewClientId = Registered.GetValue<string>('client_id');
    Assert.IsNotEmpty(NewClientId);

    var Client: TOAuthClient;
    Assert.IsTrue(FStores.Clients.TryGet(NewClientId, Client), 'client stored');
  finally
    Registered.Free;
  end;
end;

procedure TOAuthControllerTests.RegisterEndpointRejectsInvalidMetadataAsJson;
begin
  var Request := NewRequest('POST', '/register', '', 'not json', '');
  Request.ContentType := 'application/json';

  const Response = FRouter.Dispatch(Request);

  Assert.AreEqual(StatusBadRequest, Response.StatusCode);
  Assert.Contains(Response.Body, '"error":"invalid_client_metadata"');
end;

procedure TOAuthControllerTests.AuthorizeWithoutSessionRedirectsToUpstream;
begin
  const Response = FRouter.Dispatch(NewRequest('GET', '/authorize', AuthorizeQuery(RedirectUri, 'S256'), '', ''));

  Assert.AreEqual(StatusFound, Response.StatusCode, Response.Body);
  Assert.StartsWith('https://login.example.test/authorize', Response.Location);
  Assert.IsEmpty(SetCookieNamed(Response, SessionCookieName), 'no session yet');
  Assert.IsNotEmpty(SetCookieNamed(Response, LoginCookieName), 'the browser is bound to the sign-in');
end;

procedure TOAuthControllerTests.AuthorizeWithSessionRedirectsToConsent;
begin
  var Cookie: string;
  FSessions.Start(OtherUser, Cookie);
  const SessionCookie = CookieValue(Cookie);

  const Response = FRouter.Dispatch(NewRequest('GET', '/authorize', AuthorizeQuery(RedirectUri, 'S256'), '', SessionCookie));

  Assert.AreEqual(StatusFound, Response.StatusCode, Response.Body);
  Assert.StartsWith('/consent?pending=', Response.Location);
  Assert.IsTrue(IsPendingKnown(QueryParam(Response.Location, 'pending')), 'pending awaits consent');
end;

procedure TOAuthControllerTests.AuthorizeErrorAfterRedirectValidationRedirectsWithErrorAndState;
begin
  const Response = FRouter.Dispatch(NewRequest('GET', '/authorize', AuthorizeQuery(RedirectUri, 'plain'), '', ''));

  Assert.AreEqual(StatusFound, Response.StatusCode, Response.Body);
  Assert.StartsWith(RedirectUri + '?', Response.Location);
  Assert.AreEqual('invalid_request', QueryParam(Response.Location, 'error'));
  Assert.AreEqual(ClientState, QueryParam(Response.Location, 'state'));
  Assert.IsEmpty(QueryParam(Response.Location, 'code'));
end;

procedure TOAuthControllerTests.CallbackStartsSessionAndShowsConsentWithResourceName;
begin
  var PendingId: string;
  const SessionCookie = SignIn(PendingId);

  Assert.IsNotEmpty(PendingId);
  Assert.IsNotEmpty(SessionCookie);

  const Response = FRouter.Dispatch(NewRequest('GET', '/consent', 'pending=' + TNetEncoding.URL.EncodeForm(PendingId), '', SessionCookie));

  Assert.AreEqual(StatusOk, Response.StatusCode, Response.Body);
  Assert.StartsWith('text/html', Response.ContentType);
  Assert.Contains(Response.Body, 'Resource A');
  Assert.Contains(Response.Body, 'Test Client');
  Assert.Contains(Response.Body, CsrfOf(SessionCookie));
end;

procedure TOAuthControllerTests.CallbackWithUnknownStateShowsErrorPage;
begin
  const Response = FRouter.Dispatch(NewRequest('GET', '/callback/' + ProviderName, 'code=x&state=unknown', '', ''));

  Assert.AreEqual(StatusBadRequest, Response.StatusCode);
  Assert.StartsWith('text/html', Response.ContentType);
  Assert.IsEmpty(Response.Location);
  Assert.AreEqual<Integer>(0, Length(Response.SetCookies), 'no session');
end;

procedure TOAuthControllerTests.CallbackWithoutLoginCookieIsRejected;
begin
  StartAuthorizeLogin;

  const Response = FRouter.Dispatch(CallbackRequest('', ''));

  Assert.AreEqual(StatusForbidden, Response.StatusCode, Response.Body);
  Assert.StartsWith('text/html', Response.ContentType);
  Assert.IsEmpty(Response.Location);
  Assert.IsEmpty(SetCookieNamed(Response, SessionCookieName), 'no session');
  Assert.AreEqual(0, FProvider.ExchangeCount, 'the upstream code is not redeemed');
end;

procedure TOAuthControllerTests.CallbackWithOtherBrowsersLoginCookieIsRejected;
begin
  const VictimLoginCookie = StartAuthorizeLogin;
  StartAuthorizeLogin;

  // The callback URL of the second sign-in is opened in the browser of the first one.
  const Response = FRouter.Dispatch(CallbackRequest(VictimLoginCookie, ''));

  Assert.AreEqual(StatusForbidden, Response.StatusCode, Response.Body);
  Assert.IsEmpty(Response.Location);
  Assert.IsEmpty(SetCookieNamed(Response, SessionCookieName), 'no session');
  Assert.AreEqual(0, FProvider.ExchangeCount, 'the upstream code is not redeemed');
end;

procedure TOAuthControllerTests.LoginCookieIsHttpOnlySecureLaxAndClearedAfterSignIn;
begin
  const Authorize = FRouter.Dispatch(NewRequest('GET', '/authorize', AuthorizeQuery(RedirectUri, 'S256'), '', ''));
  const LoginCookie = SetCookieNamed(Authorize, LoginCookieName);

  Assert.Contains(LoginCookie, '; HttpOnly');
  Assert.Contains(LoginCookie, '; Secure');
  Assert.Contains(LoginCookie, '; SameSite=Lax');
  Assert.Contains(LoginCookie, Format('; Max-Age=%d', [FSettings.PendingSeconds]));

  const Callback = FRouter.Dispatch(CallbackRequest(CookieValue(LoginCookie), ''));

  Assert.AreEqual(StatusFound, Callback.StatusCode, Callback.Body);
  Assert.Contains(SetCookieNamed(Callback, LoginCookieName), 'Max-Age=0');
end;

procedure TOAuthControllerTests.ConsentApproveRedirectsToClientWithCodeAndState;
begin
  var PendingId: string;
  const SessionCookie = SignIn(PendingId);
  const Body = ConsentBody(PendingId, CsrfOf(SessionCookie), 'approve');

  const Response = FRouter.Dispatch(NewRequest('POST', '/consent', '', Body, SessionCookie));

  Assert.AreEqual(StatusFound, Response.StatusCode, Response.Body);
  Assert.StartsWith(RedirectUri + '?', Response.Location);
  Assert.IsNotEmpty(QueryParam(Response.Location, 'code'));
  Assert.AreEqual(ClientState, QueryParam(Response.Location, 'state'));
end;

procedure TOAuthControllerTests.ConsentDenyRedirectsToClientWithAccessDenied;
begin
  var PendingId: string;
  const SessionCookie = SignIn(PendingId);
  const Body = ConsentBody(PendingId, CsrfOf(SessionCookie), 'deny');

  const Response = FRouter.Dispatch(NewRequest('POST', '/consent', '', Body, SessionCookie));

  Assert.AreEqual(StatusFound, Response.StatusCode, Response.Body);
  Assert.StartsWith(RedirectUri + '?', Response.Location);
  Assert.AreEqual('access_denied', QueryParam(Response.Location, 'error'));
  Assert.AreEqual(ClientState, QueryParam(Response.Location, 'state'));
  Assert.IsFalse(IsPendingKnown(PendingId), 'pending ended');
end;

procedure TOAuthControllerTests.ConsentPostWithoutCsrfIsRejected;
begin
  var PendingId: string;
  const SessionCookie = SignIn(PendingId);

  const CsrfValues: TArray<string> = ['', 'wrong-token'];
  for var Csrf in CsrfValues do
  begin
    const Body = ConsentBody(PendingId, Csrf, 'approve');

    const Response = FRouter.Dispatch(NewRequest('POST', '/consent', '', Body, SessionCookie));

    Assert.AreEqual(StatusForbidden, Response.StatusCode, Csrf);
    Assert.IsEmpty(Response.Location, Csrf);
  end;

  Assert.IsTrue(IsPendingKnown(PendingId), 'no grant was issued');
end;

procedure TOAuthControllerTests.ConsentPostWithOtherUsersSessionIsRejected;
begin
  var PendingId: string;
  SignIn(PendingId);

  var Cookie: string;
  const OtherSession = FSessions.Start(OtherUser, Cookie);
  const OtherCookie = CookieValue(Cookie);

  const Decisions: TArray<string> = ['approve', 'deny'];
  for var Decision in Decisions do
  begin
    const Body = ConsentBody(PendingId, OtherSession.CsrfToken, Decision);

    const Response = FRouter.Dispatch(NewRequest('POST', '/consent', '', Body, OtherCookie));

    Assert.AreEqual(StatusForbidden, Response.StatusCode, Decision);
    Assert.IsEmpty(Response.Location, Decision);
  end;

  Assert.IsTrue(IsPendingKnown(PendingId), 'no grant was issued and the request was not denied');
end;

procedure TOAuthControllerTests.ConsentWithoutSessionIsRejected;
begin
  var PendingId: string;
  SignIn(PendingId);

  const PageResponse = FRouter.Dispatch(NewRequest('GET', '/consent', 'pending=' + TNetEncoding.URL.EncodeForm(PendingId), '', ''));
  const PostResponse = FRouter.Dispatch(NewRequest('POST', '/consent', '', ConsentBody(PendingId, 'x', 'approve'), ''));

  Assert.AreEqual(StatusForbidden, PageResponse.StatusCode);
  Assert.AreEqual(StatusForbidden, PostResponse.StatusCode);
  Assert.IsEmpty(PostResponse.Location);
  Assert.IsTrue(IsPendingKnown(PendingId), 'no grant was issued');
end;

procedure TOAuthControllerTests.ConsentPageCannotBeFramed;
begin
  var PendingId: string;
  const SessionCookie = SignIn(PendingId);

  const Response = FRouter.Dispatch(NewRequest('GET', '/consent', 'pending=' + TNetEncoding.URL.EncodeForm(PendingId), '', SessionCookie));

  Assert.AreEqual('DENY', HeaderValue(Response, 'X-Frame-Options'));
  Assert.Contains(HeaderValue(Response, 'Content-Security-Policy'), 'frame-ancestors ''none''');
  Assert.AreEqual('no-store', HeaderValue(Response, 'Cache-Control'));
end;

procedure TOAuthControllerTests.UnregisteredRedirectShowsErrorPageWithoutRedirect;
begin
  const Response = FRouter.Dispatch(NewRequest('GET', '/authorize', AuthorizeQuery(UnregisteredRedirectUri, 'S256'), '', ''));

  Assert.AreEqual(StatusBadRequest, Response.StatusCode);
  Assert.IsEmpty(Response.Location);
  Assert.StartsWith('text/html', Response.ContentType);
  Assert.DoesNotContain(Response.Body, UnregisteredRedirectUri);
end;

procedure TOAuthControllerTests.UnknownClientShowsErrorPageWithoutRedirect;
begin
  const Query = AuthorizeQuery(RedirectUri, 'S256').Replace('client_id=' + ClientId, 'client_id=unknown');

  const Response = FRouter.Dispatch(NewRequest('GET', '/authorize', Query, '', ''));

  Assert.AreEqual(StatusBadRequest, Response.StatusCode);
  Assert.IsEmpty(Response.Location);
  Assert.StartsWith('text/html', Response.ContentType);
end;

procedure TOAuthControllerTests.TokenEndpointIssuesTokensAsJsonWithNoStore;
begin
  const Code = ObtainCode;

  const Response = FRouter.Dispatch(NewRequest('POST', '/token', '', TokenBody(Code), ''));

  Assert.AreEqual(StatusOk, Response.StatusCode, Response.Body);
  Assert.StartsWith('application/json', Response.ContentType);
  Assert.AreEqual('no-store', HeaderValue(Response, 'Cache-Control'));
  Assert.AreEqual('no-cache', HeaderValue(Response, 'Pragma'));

  const Tokens = TJSONObject.ParseJSONValue(Response.Body) as TJSONObject;
  try
    Assert.IsNotEmpty(Tokens.GetValue<string>('access_token'));
    Assert.IsNotEmpty(Tokens.GetValue<string>('refresh_token'));
    Assert.AreEqual('Bearer', Tokens.GetValue<string>('token_type'));
    Assert.AreEqual(FSettings.AccessTokenSeconds, Tokens.GetValue<Integer>('expires_in'));
    Assert.AreEqual('mcp', Tokens.GetValue<string>('scope'));
  finally
    Tokens.Free;
  end;
end;

procedure TOAuthControllerTests.TokenEndpointErrorsAreJsonWithNoStore;
begin
  const Response = FRouter.Dispatch(NewRequest('POST', '/token', '', TokenBody('unknown-code'), ''));

  Assert.AreEqual(StatusBadRequest, Response.StatusCode);
  Assert.StartsWith('application/json', Response.ContentType);
  Assert.AreEqual('no-store', HeaderValue(Response, 'Cache-Control'));
  Assert.AreEqual('no-cache', HeaderValue(Response, 'Pragma'));

  const Error = TJSONObject.ParseJSONValue(Response.Body) as TJSONObject;
  try
    Assert.AreEqual('invalid_grant', Error.GetValue<string>('error'));
    Assert.IsNotEmpty(Error.GetValue<string>('error_description'));
  finally
    Error.Free;
  end;
end;

procedure TOAuthControllerTests.TokenEndpointRequiresClientId;
begin
  const Body = TokenBody(ObtainCode).Replace('client_id=' + ClientId, 'client_id=');

  const Response = FRouter.Dispatch(NewRequest('POST', '/token', '', Body, ''));

  Assert.AreEqual(StatusBadRequest, Response.StatusCode);
  Assert.Contains(Response.Body, '"error":"invalid_request"');
  Assert.AreEqual('no-store', HeaderValue(Response, 'Cache-Control'));
end;

procedure TOAuthControllerTests.RevokeEndpointRevokesTheFamily;
begin
  const TokenResponse = FRouter.Dispatch(NewRequest('POST', '/token', '', TokenBody(ObtainCode), ''));
  const Tokens = TJSONObject.ParseJSONValue(TokenResponse.Body) as TJSONObject;
  try
    const RefreshToken = Tokens.GetValue<string>('refresh_token');
    const AccessToken = Tokens.GetValue<string>('access_token');
    const Body = Format('token=%s&client_id=%s', [TNetEncoding.URL.EncodeForm(RefreshToken), ClientId]);

    const Response = FRouter.Dispatch(NewRequest('POST', '/revoke', '', Body, ''));

    Assert.AreEqual(StatusOk, Response.StatusCode, Response.Body);

    var Issued: TIssuedToken;
    Assert.IsFalse(FStores.Tokens.TryGet(TTokenHash.Of(AccessToken), Issued), 'access token of the family is gone');
  finally
    Tokens.Free;
  end;
end;

procedure TOAuthControllerTests.SessionCookieIsHttpOnlySecureLax;
begin
  const LoginCookie = StartAuthorizeLogin;

  const Response = FRouter.Dispatch(CallbackRequest(LoginCookie, ''));

  const Cookie = SetCookieNamed(Response, SessionCookieName);
  Assert.StartsWith(SessionCookieName + '=', Cookie);
  Assert.Contains(Cookie, '; HttpOnly');
  Assert.Contains(Cookie, '; Secure');
  Assert.Contains(Cookie, '; SameSite=Lax');
  Assert.Contains(Cookie, '; Path=/');
end;

procedure TOAuthControllerTests.SessionStoreHoldsOnlyTheHash;
begin
  var Cookie: string;
  const Session = FSessions.Start(OtherUser, Cookie);
  const SessionId = CookieValue(Cookie);

  var Stored: TWebSession;
  Assert.IsFalse(FStores.Sessions.TryGet(SessionId, Stored), 'raw id is not a key');
  Assert.IsTrue(FStores.Sessions.TryGet(TTokenHash.Of(SessionId), Stored), 'hash is the key');
  Assert.AreEqual(Session.IdHash, Stored.IdHash);
  Assert.AreEqual(OtherUser, Stored.UserId);
  Assert.IsNotEmpty(Stored.CsrfToken);

  FSettings.SecureCookies := False;
  const InsecureSessions: IWebSessions = TWebSessions.Create(FStores.Sessions, TTokenGenerator.Create, FSettings, FClockReference);
  InsecureSessions.Start(OtherUser, Cookie);
  Assert.DoesNotContain(Cookie, 'Secure');
  Assert.StartsWith('mcpauth_session=', Cookie, 'the __Host- prefix needs Secure');
end;

procedure TOAuthControllerTests.UnknownPathRenders404Page;
begin
  const Response = FRouter.Dispatch(NewRequest('GET', '/does-not-exist', '', '', ''));

  Assert.AreEqual(StatusNotFound, Response.StatusCode);
  Assert.StartsWith('text/html', Response.ContentType);
  Assert.Contains(Response.Body, '<html');
end;

procedure TOAuthControllerTests.FirstRegisteredRouteWins;
begin
  const Router = TWebRouter.Create;
  try
    Router.Add('GET', '/x',
      function(const Request: TWebRequest): TWebResponse
      begin
        Result := TWebResponse.Json(StatusOk, '"first"');
      end);
    Router.Add('GET', '/x',
      function(const Request: TWebRequest): TWebResponse
      begin
        Result := TWebResponse.Json(StatusOk, '"second"');
      end);
    Router.AddPrefix('GET', '/x',
      function(const Request: TWebRequest): TWebResponse
      begin
        Result := TWebResponse.Json(StatusOk, '"prefix"');
      end);

    Assert.AreEqual('"first"', Router.Dispatch(NewRequest('GET', '/x', '', '', '')).Body);
    Assert.AreEqual('"prefix"', Router.Dispatch(NewRequest('GET', '/x/y', '', '', '')).Body);
    Assert.AreEqual(StatusNotFound, Router.Dispatch(NewRequest('POST', '/x', '', '', '')).StatusCode);
  finally
    Router.Free;
  end;
end;

procedure TOAuthControllerTests.UnknownRouteOnRouterWithoutPagesIsJson404;
begin
  const Router = TWebRouter.Create;
  try
    const Response = Router.Dispatch(NewRequest('GET', '/nothing', '', '', ''));

    Assert.AreEqual(StatusNotFound, Response.StatusCode);
    Assert.StartsWith('application/json', Response.ContentType);
    Assert.Contains(Response.Body, '"error":"not_found"');
  finally
    Router.Free;
  end;
end;

procedure TOAuthControllerTests.FormFieldDecodesPlusAndUtf8;
begin
  const Request = NewRequest('POST', '/x', 'a=1&name=caf%C3%A9+au+lait&empty=&bad=%zz', 'first=1&first=2&space=a+b%2Bc', '');

  const Expected = Format('caf%s au lait', [Char($E9)]);
  Assert.AreEqual(Expected, Request.QueryParam('name'));
  Assert.AreEqual('', Request.QueryParam('empty'));
  Assert.AreEqual('%zz', Request.QueryParam('bad'));
  Assert.AreEqual('', Request.QueryParam('missing'));
  Assert.AreEqual('1', Request.FormField('first'));
  Assert.AreEqual('a b+c', Request.FormField('space'));
end;

end.
