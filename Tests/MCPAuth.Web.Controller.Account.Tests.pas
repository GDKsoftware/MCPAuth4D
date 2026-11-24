unit MCPAuth.Web.Controller.Account.Tests;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  MCPAuth.Fakes.Clock,
  MCPAuth.Fakes.UpstreamProvider,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Store.Interfaces,
  MCPAuth.Identity.Interfaces,
  MCPAuth.Identity.Types,
  MCPAuth.Upstream.Interfaces,
  MCPAuth.OAuth.Settings,
  MCPAuth.Web.Types,
  MCPAuth.Web.Router,
  MCPAuth.Web.Session.Interfaces,
  MCPAuth.Web.Controller.OAuth,
  MCPAuth.Web.Controller.Account;

type
  [TestFixture]
  TAccountControllerTests = class
  private
    FClock: TFakeClock;
    FClockReference: IClock;
    FStores: TStoreSet;
    FProvider: TFakeUpstreamProvider;
    FProviderReference: IUpstreamProvider;
    FSettings: TMCPAuthSettings;
    FAccounts: ILinkedAccounts;
    FSessions: IWebSessions;
    FOAuthController: TOAuthController;
    FAccountController: TAccountController;
    FRouter: TWebRouter;

    class function CookieValue(const SetCookie: string): string; static;
    class function SetCookieNamed(const Response: TWebResponse; const Name: string): string; static;
    class function FindLibraryTemplatesPath: string; static;
    class function UserKey(const ObjectId: string): TAccountKey; static;

    function BuildResourceRegistryJson: string;
    procedure BuildHosts(const Providers: TArray<IUpstreamProvider>);
    procedure FreeHosts;
    function NewRequest(const Method, Path, Query, Body, SessionCookie: string): TWebRequest;
    function CallbackRequest(const LoginCookie, SessionCookie: string): TWebRequest;
    function SignInAs(const ObjectId, DisplayName, UserName: string): string;
    function StartLinking(const SessionCookie: string): string;
    function PostForm(const Path, Body, SessionCookie: string): TWebResponse;
    function CsrfOf(const SessionCookie: string): string;
    function UserIdOf(const SessionCookie: string): string;
    function KeyAndCsrfBody(const Key: TAccountKey; const Csrf: string): string;
    procedure AddAccount(const UserId, ObjectId, DisplayName: string);
    procedure AddGrant(const UserId, FamilyId, ClientId: string);
    procedure MarkNeedsReconnect(const UserId: string; const Key: TAccountKey);
    function IsSessionStored(const SessionCookie: string): Boolean;
    function CountAccounts(const UserId: string): Integer;
    function CountGrants(const UserId: string): Integer;

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure RootRedirectsToAccount;

    [Test]
    procedure AccountPageWithoutSessionRedirectsToLogin;

    [Test]
    procedure AccountPageListsOwnAccountsAndGrantsOnly;

    [Test]
    procedure AccountPageShowsReconnect;

    [Test]
    procedure ReconnectClearsNeedsReconnect;

    [Test]
    procedure ReconnectOfOtherUsersAccountIsNotFound;

    [Test]
    procedure UnlinkWithoutCsrfIsRejected;

    [Test]
    procedure UnlinkRemovesTheAccount;

    [Test]
    procedure UnlinkLastAccountRedirectsToAccountPage;

    [Test]
    procedure RevokeRemovesGrant;

    [Test]
    procedure RevokeOfOtherUsersGrantIsIgnored;

    [Test]
    procedure LinkRedirectsToUpstream;

    [Test]
    procedure LinkWithoutCsrfIsRejected;

    [Test]
    procedure LinkKeepsTheSession;

    [Test]
    procedure LinkCallbackFromOtherBrowserDoesNotLink;

    [Test]
    procedure LinkCallbackWithOtherSessionUserIsRejected;

    [Test]
    procedure LinkingAccountOfOtherUserCompletes;

    [Test]
    procedure AccountPageShowsTheSignInAccount;

    [Test]
    procedure AccountPageWithoutSignInAccountOmitsIt;

    [Test]
    procedure PostsWithoutSessionAreRejected;

    [Test]
    procedure LoginWithOneProviderGoesStraightToIt;

    [Test]
    procedure LoginWithSeveralProvidersShowsChoice;

    [Test]
    procedure LoginWithChosenProviderRedirectsToIt;

    [Test]
    procedure LoginWithUnknownProviderShowsError;

    [Test]
    procedure LogoutRequiresCsrf;

    [Test]
    procedure LogoutEndsTheSession;

    [Test]
    procedure InternalRoutesAreNotOnPublicRouter;
  end;

implementation

uses
  System.IOUtils,
  System.DateUtils,
  System.NetEncoding,
  Spring.Collections,
  MCPAuth.Secret.Hash,
  MCPAuth.Secret.Token,
  MCPAuth.Secret.KeyRing,
  MCPAuth.Secret.AesGcm,
  MCPAuth.Store.Memory,
  MCPAuth.Identity.Accounts,
  MCPAuth.Identity.Access.AllowAll,
  MCPAuth.Resource.Registry.Json,
  MCPAuth.Upstream.Types,
  MCPAuth.Upstream.Providers,
  MCPAuth.OAuth.Types,
  MCPAuth.OAuth.Interfaces,
  MCPAuth.OAuth.Server,
  MCPAuth.Web.Session,
  MCPAuth.Web.Page.WebStencils;

const
  Issuer = 'https://auth.example.test';
  ProviderName = 'fake';
  OtherProviderName = 'other';
  TenantId = 'tenant-1';
  ClientId = 'client-1';
  OtherClientId = 'client-2';
  ResourceA = 'https://a.example.test/mcp';
  UpstreamCode = 'upstream-code';
  KeyId = 'k1';
  KeyLength = 32;
  SessionCookieName = '__Host-mcpauth_session';
  LoginCookieName = '__Host-mcpauth_login';
  FormContentType = 'application/x-www-form-urlencoded';
  UpstreamLoginPrefix = 'https://login.example.test/authorize';
  StatusOk = 200;
  StatusFound = 302;
  StatusBadRequest = 400;
  StatusForbidden = 403;
  StatusNotFound = 404;
  FirstObjectId = 'object-1';
  SecondObjectId = 'object-2';
  OtherObjectId = 'object-other';

{ TAccountControllerTests }

class function TAccountControllerTests.CookieValue(const SetCookie: string): string;
begin
  const Pair = SetCookie.Split([';'])[0];
  const SeparatorIndex = Pair.IndexOf('=');

  Result := Pair.Substring(SeparatorIndex + 1);
end;

class function TAccountControllerTests.SetCookieNamed(const Response: TWebResponse; const Name: string): string;
begin
  for var SetCookie in Response.SetCookies do
  begin
    if SetCookie.StartsWith(Name + '=') then
      Exit(SetCookie);
  end;

  Result := '';
end;

class function TAccountControllerTests.FindLibraryTemplatesPath: string;
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

class function TAccountControllerTests.UserKey(const ObjectId: string): TAccountKey;
begin
  Result.Provider := ProviderName;
  Result.TenantId := TenantId;
  Result.ObjectId := ObjectId;
end;

procedure TAccountControllerTests.Setup;
begin
  FClock := TFakeClock.Create(EncodeDateTime(2026, 1, 2, 3, 4, 5, 0));
  FClockReference := FClock;
  FStores := TMemoryStore.CreateSet(FClockReference);
  FProvider := TFakeUpstreamProvider.Create(ProviderName);
  FProviderReference := FProvider;
  FSettings := TMCPAuthSettings.Defaults(Issuer);

  var Client := Default(TOAuthClient);
  Client.ClientId     := ClientId;
  Client.ClientName   := 'Test Client';
  Client.RedirectUris := ['http://localhost:9000/callback'];
  Client.CreatedAtUtc := FClock.NowUtc;
  FStores.Clients.Save(Client);

  Client.ClientId   := OtherClientId;
  Client.ClientName := 'Other Client';
  FStores.Clients.Save(Client);

  BuildHosts([FProviderReference]);
end;

procedure TAccountControllerTests.TearDown;
begin
  FreeHosts;
  FProviderReference := nil;
  FStores := Default(TStoreSet);
  FClockReference := nil;
end;

function TAccountControllerTests.BuildResourceRegistryJson: string;
begin
  const Hash = TTokenHash.Of('service-secret');
  const Entry = '{"resource":"%s","name":"%s","service_id":"%s","service_secret_sha256":"%s",' +
                '"providers":[{"provider":"fake","scopes":["read"]}]}';

  Result := Format('{"resources":[%s]}', [Format(Entry, [ResourceA, 'Resource A', 'service-a', Hash])]);
end;

procedure TAccountControllerTests.BuildHosts(const Providers: TArray<IUpstreamProvider>);
begin
  var Key: TBytes;
  SetLength(Key, KeyLength);
  FillChar(Key[0], KeyLength, 5);
  const Keys = TCollections.CreateDictionary<string, TBytes>;
  Keys[KeyId] := Key;
  const Protector = TAesGcmProtector.Create(TKeyRing.Create(KeyId, Keys));

  const Tokens = TTokenGenerator.Create;
  const UpstreamProviders = TUpstreamProviders.Create(Providers);
  FAccounts := TLinkedAccounts.Create(FStores.Users, FStores.LoginIdentities, FStores.LinkedAccounts, Protector, TAllowAllAccessPolicy.Create, UpstreamProviders, FClockReference);
  const Registry = TJsonResourceRegistry.FromJson(BuildResourceRegistryJson);
  const Server: IAuthorizationServer = TAuthorizationServer.Create(FStores, Registry, UpstreamProviders, FAccounts, Tokens, FSettings, FClockReference);
  const Pages = TWebStencilsPageRenderer.Create('', FindLibraryTemplatesPath);

  FSessions := TWebSessions.Create(FStores.Sessions, Tokens, FSettings, FClockReference);
  FOAuthController := TOAuthController.Create(Server, FStores.Clients, FSessions, Pages, Tokens, FSettings, FClockReference);
  FAccountController := TAccountController.Create(Server, FAccounts, Registry, UpstreamProviders, FSessions, Pages, FStores, FSettings);

  FRouter := TWebRouter.Create;
  FOAuthController.Register(FRouter);
  FAccountController.Register(FRouter);
end;

procedure TAccountControllerTests.FreeHosts;
begin
  FreeAndNil(FRouter);
  FreeAndNil(FAccountController);
  FreeAndNil(FOAuthController);
  FSessions := nil;
  FAccounts := nil;
end;

function TAccountControllerTests.NewRequest(const Method, Path, Query, Body, SessionCookie: string): TWebRequest;
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

function TAccountControllerTests.CallbackRequest(const LoginCookie, SessionCookie: string): TWebRequest;
begin
  const CallbackQuery = Format('code=%s&state=%s', [UpstreamCode, TNetEncoding.URL.EncodeForm(FProvider.LastState)]);

  Result := NewRequest('GET', '/callback/' + ProviderName, CallbackQuery, '', SessionCookie);
  if not LoginCookie.IsEmpty then
    Result.Cookies[LoginCookieName] := LoginCookie;
end;

function TAccountControllerTests.SignInAs(const ObjectId, DisplayName, UserName: string): string;
begin
  FProvider.SetIdentity(TenantId, ObjectId, DisplayName, UserName);

  const Login = FRouter.Dispatch(NewRequest('GET', '/login', '', '', ''));
  Assert.AreEqual(StatusFound, Login.StatusCode, Login.Body);
  Assert.StartsWith(UpstreamLoginPrefix, Login.Location);

  const LoginCookie = CookieValue(SetCookieNamed(Login, LoginCookieName));
  const Callback = FRouter.Dispatch(CallbackRequest(LoginCookie, ''));

  Assert.AreEqual(StatusFound, Callback.StatusCode, Callback.Body);
  Assert.AreEqual('/account', Callback.Location);
  Result := CookieValue(SetCookieNamed(Callback, SessionCookieName));
end;

function TAccountControllerTests.StartLinking(const SessionCookie: string): string;
begin
  const Body = Format('provider=%s&csrf=%s', [ProviderName, TNetEncoding.URL.EncodeForm(CsrfOf(SessionCookie))]);
  const Response = PostForm('/account/link', Body, SessionCookie);
  Assert.AreEqual(StatusFound, Response.StatusCode, Response.Body);

  Result := CookieValue(SetCookieNamed(Response, LoginCookieName));
end;

function TAccountControllerTests.PostForm(const Path, Body, SessionCookie: string): TWebResponse;
begin
  Result := FRouter.Dispatch(NewRequest('POST', Path, '', Body, SessionCookie));
end;

function TAccountControllerTests.CsrfOf(const SessionCookie: string): string;
begin
  var Session: TWebSession;
  Assert.IsTrue(FStores.Sessions.TryGet(TTokenHash.Of(SessionCookie), Session), 'session stored by hash');

  Result := Session.CsrfToken;
end;

function TAccountControllerTests.UserIdOf(const SessionCookie: string): string;
begin
  var Session: TWebSession;
  Assert.IsTrue(FStores.Sessions.TryGet(TTokenHash.Of(SessionCookie), Session), 'session stored by hash');

  Result := Session.UserId;
end;

function TAccountControllerTests.KeyAndCsrfBody(const Key: TAccountKey; const Csrf: string): string;
begin
  Result := Format('key=%s&csrf=%s', [TNetEncoding.URL.EncodeForm(Key.Value), TNetEncoding.URL.EncodeForm(Csrf)]);
end;

procedure TAccountControllerTests.AddAccount(const UserId, ObjectId, DisplayName: string);
begin
  var Tokens := Default(TUpstreamTokens);
  Tokens.AccessToken := 'access';
  Tokens.RefreshToken := 'refresh-' + ObjectId;
  Tokens.Scope := 'openid offline_access';
  Tokens.Identity.Key := UserKey(ObjectId);
  Tokens.Identity.DisplayName := DisplayName;
  Tokens.Identity.UserName := ObjectId + '@example.test';

  FAccounts.Link(UserId, Tokens);
end;

procedure TAccountControllerTests.AddGrant(const UserId, FamilyId, ClientId: string);
begin
  var Token := Default(TIssuedToken);
  Token.Hash         := TTokenHash.Of('refresh-' + FamilyId);
  Token.Kind         := TTokenKind.Refresh;
  Token.FamilyId     := FamilyId;
  Token.UserId       := UserId;
  Token.ClientId     := ClientId;
  Token.Resource     := ResourceA;
  Token.CreatedAtUtc := FClock.NowUtc;
  Token.ExpiresAtUtc := IncDay(FClock.NowUtc, 1);
  FStores.Tokens.Save(Token);
end;

procedure TAccountControllerTests.MarkNeedsReconnect(const UserId: string; const Key: TAccountKey);
begin
  var Account: TLinkedAccount;
  Assert.IsTrue(FStores.LinkedAccounts.TryFind(UserId, Key, Account), 'account exists');

  Account.NeedsReconnect := True;
  FStores.LinkedAccounts.Save(Account);
end;

function TAccountControllerTests.IsSessionStored(const SessionCookie: string): Boolean;
begin
  var Session: TWebSession;
  Result := FStores.Sessions.TryGet(TTokenHash.Of(SessionCookie), Session);
end;

function TAccountControllerTests.CountAccounts(const UserId: string): Integer;
begin
  Result := FAccounts.ListForUser(UserId).Count;
end;

function TAccountControllerTests.CountGrants(const UserId: string): Integer;
begin
  Result := FStores.Tokens.ListFamiliesForUser(UserId).Count;
end;

procedure TAccountControllerTests.RootRedirectsToAccount;
begin
  const Response = FRouter.Dispatch(NewRequest('GET', '/', '', '', ''));

  Assert.AreEqual(StatusFound, Response.StatusCode);
  Assert.AreEqual('/account', Response.Location);
end;

procedure TAccountControllerTests.AccountPageWithoutSessionRedirectsToLogin;
begin
  const Response = FRouter.Dispatch(NewRequest('GET', '/account', '', '', ''));

  Assert.AreEqual(StatusFound, Response.StatusCode);
  Assert.AreEqual('/login', Response.Location);
end;

procedure TAccountControllerTests.AccountPageListsOwnAccountsAndGrantsOnly;
begin
  const OtherCookie = SignInAs(OtherObjectId, 'Intruder Name', 'intruder@example.test');
  AddGrant(UserIdOf(OtherCookie), 'family-other', OtherClientId);

  const SessionCookie = SignInAs(FirstObjectId, 'Test User', 'user@example.test');
  const UserId = UserIdOf(SessionCookie);
  AddGrant(UserId, 'family-own', ClientId);

  const Response = FRouter.Dispatch(NewRequest('GET', '/account', '', '', SessionCookie));

  Assert.AreEqual(StatusOk, Response.StatusCode, Response.Body);
  Assert.StartsWith('text/html', Response.ContentType);
  Assert.Contains(Response.Body, 'Test User');
  Assert.Contains(Response.Body, 'user@example.test');
  Assert.Contains(Response.Body, 'Resource A');
  Assert.Contains(Response.Body, 'Test Client');
  Assert.Contains(Response.Body, 'family-own');
  Assert.Contains(Response.Body, '2026-01-02T03:04:05Z');
  Assert.Contains(Response.Body, '2 Jan 2026, 03:04 UTC');
  Assert.Contains(Response.Body, CsrfOf(SessionCookie));
  Assert.Contains(Response.Body, 'value="fake"');
  Assert.IsFalse(Response.Body.Contains('Intruder Name'), 'other user''s account');
  Assert.IsFalse(Response.Body.Contains('intruder@example.test'), 'other user''s user name');
  Assert.IsFalse(Response.Body.Contains('family-other'), 'other user''s grant');
  Assert.IsFalse(Response.Body.Contains('Other Client'), 'other user''s client');
end;

procedure TAccountControllerTests.AccountPageShowsReconnect;
begin
  const SessionCookie = SignInAs(FirstObjectId, 'Test User', 'user@example.test');

  const Healthy = FRouter.Dispatch(NewRequest('GET', '/account', '', '', SessionCookie));
  Assert.IsFalse(Healthy.Body.Contains('action="/account/reconnect"'), 'no reconnect while connected');

  MarkNeedsReconnect(UserIdOf(SessionCookie), UserKey(FirstObjectId));
  const Response = FRouter.Dispatch(NewRequest('GET', '/account', '', '', SessionCookie));

  Assert.AreEqual(StatusOk, Response.StatusCode, Response.Body);
  Assert.Contains(Response.Body, 'Needs reconnect');
  Assert.Contains(Response.Body, 'action="/account/reconnect"');
  Assert.Contains(Response.Body, 'Reconnect');
end;

procedure TAccountControllerTests.ReconnectClearsNeedsReconnect;
begin
  const SessionCookie = SignInAs(FirstObjectId, 'Test User', 'user@example.test');
  const UserId = UserIdOf(SessionCookie);
  const Key = UserKey(FirstObjectId);
  MarkNeedsReconnect(UserId, Key);

  const Reconnect = PostForm('/account/reconnect', KeyAndCsrfBody(Key, CsrfOf(SessionCookie)), SessionCookie);
  Assert.AreEqual(StatusFound, Reconnect.StatusCode, Reconnect.Body);
  Assert.StartsWith(UpstreamLoginPrefix, Reconnect.Location);

  FProvider.RefreshToken := 'refreshed-after-reconnect';
  const LoginCookie = CookieValue(SetCookieNamed(Reconnect, LoginCookieName));
  const Callback = FRouter.Dispatch(CallbackRequest(LoginCookie, SessionCookie));
  Assert.AreEqual('/account', Callback.Location, Callback.Body);

  var Account: TLinkedAccount;
  Assert.IsTrue(FStores.LinkedAccounts.TryFind(UserId, Key, Account), 'account kept');
  Assert.IsFalse(Account.NeedsReconnect, 'flag cleared');
  Assert.AreEqual<Integer>(1, CountAccounts(UserId), 'same account, not a second one');

  FAccounts.GetAccessToken(UserId, Key, []);
  Assert.AreEqual('refreshed-after-reconnect', FProvider.LastRefreshInput, 'the new refresh token replaced the old one');
end;

procedure TAccountControllerTests.ReconnectOfOtherUsersAccountIsNotFound;
begin
  SignInAs(OtherObjectId, 'Intruder Name', 'intruder@example.test');
  const SessionCookie = SignInAs(FirstObjectId, 'Test User', 'user@example.test');

  const Response = PostForm('/account/reconnect', KeyAndCsrfBody(UserKey(OtherObjectId), CsrfOf(SessionCookie)), SessionCookie);

  Assert.AreEqual(StatusNotFound, Response.StatusCode, Response.Body);
  Assert.IsEmpty(Response.Location);
end;

procedure TAccountControllerTests.UnlinkWithoutCsrfIsRejected;
begin
  const SessionCookie = SignInAs(FirstObjectId, 'Test User', 'user@example.test');
  const UserId = UserIdOf(SessionCookie);
  AddAccount(UserId, SecondObjectId, 'Second User');

  const WithoutToken = PostForm('/account/unlink', KeyAndCsrfBody(UserKey(SecondObjectId), ''), SessionCookie);
  const WithWrongToken = PostForm('/account/unlink', KeyAndCsrfBody(UserKey(SecondObjectId), 'wrong'), SessionCookie);

  Assert.AreEqual(StatusForbidden, WithoutToken.StatusCode);
  Assert.AreEqual(StatusForbidden, WithWrongToken.StatusCode);
  Assert.IsEmpty(WithWrongToken.Location);
  Assert.AreEqual<Integer>(2, CountAccounts(UserId), 'nothing unlinked');
end;

procedure TAccountControllerTests.UnlinkRemovesTheAccount;
begin
  const SessionCookie = SignInAs(FirstObjectId, 'Test User', 'user@example.test');
  const UserId = UserIdOf(SessionCookie);
  AddAccount(UserId, SecondObjectId, 'Second User');

  const Response = PostForm('/account/unlink', KeyAndCsrfBody(UserKey(SecondObjectId), CsrfOf(SessionCookie)), SessionCookie);

  Assert.AreEqual(StatusFound, Response.StatusCode, Response.Body);
  Assert.AreEqual('/account', Response.Location);
  Assert.AreEqual<Integer>(1, CountAccounts(UserId));
end;

procedure TAccountControllerTests.UnlinkLastAccountRedirectsToAccountPage;
begin
  const SessionCookie = SignInAs(FirstObjectId, 'Test User', 'user@example.test');
  const UserId = UserIdOf(SessionCookie);

  const Response = PostForm('/account/unlink', KeyAndCsrfBody(UserKey(FirstObjectId), CsrfOf(SessionCookie)), SessionCookie);

  Assert.AreEqual(StatusFound, Response.StatusCode, Response.Body);
  Assert.AreEqual('/account', Response.Location);
  Assert.AreEqual<Integer>(0, CountAccounts(UserId), 'account removed');
end;

procedure TAccountControllerTests.RevokeRemovesGrant;
begin
  const SessionCookie = SignInAs(FirstObjectId, 'Test User', 'user@example.test');
  const UserId = UserIdOf(SessionCookie);
  AddGrant(UserId, 'family-own', ClientId);

  const Response = PostForm('/account/revoke', Format('family=family-own&csrf=%s', [CsrfOf(SessionCookie)]), SessionCookie);

  Assert.AreEqual(StatusFound, Response.StatusCode, Response.Body);
  Assert.AreEqual('/account', Response.Location);
  Assert.AreEqual<Integer>(0, CountGrants(UserId));
end;

procedure TAccountControllerTests.RevokeOfOtherUsersGrantIsIgnored;
begin
  const OtherCookie = SignInAs(OtherObjectId, 'Intruder Name', 'intruder@example.test');
  const OtherUserId = UserIdOf(OtherCookie);
  AddGrant(OtherUserId, 'family-other', OtherClientId);
  const SessionCookie = SignInAs(FirstObjectId, 'Test User', 'user@example.test');

  PostForm('/account/revoke', Format('family=family-other&csrf=%s', [CsrfOf(SessionCookie)]), SessionCookie);

  Assert.AreEqual<Integer>(1, CountGrants(OtherUserId), 'grant of the other user kept');
end;

procedure TAccountControllerTests.LinkRedirectsToUpstream;
begin
  const SessionCookie = SignInAs(FirstObjectId, 'Test User', 'user@example.test');
  const Body = Format('provider=%s&csrf=%s', [ProviderName, TNetEncoding.URL.EncodeForm(CsrfOf(SessionCookie))]);

  const Response = PostForm('/account/link', Body, SessionCookie);

  Assert.AreEqual(StatusFound, Response.StatusCode, Response.Body);
  Assert.StartsWith(UpstreamLoginPrefix, Response.Location);
  Assert.Contains(Response.Location, TNetEncoding.URL.EncodeForm(FProvider.LastState));
end;

procedure TAccountControllerTests.LinkWithoutCsrfIsRejected;
begin
  const SessionCookie = SignInAs(FirstObjectId, 'Test User', 'user@example.test');

  const Response = PostForm('/account/link', Format('provider=%s&csrf=wrong', [ProviderName]), SessionCookie);

  Assert.AreEqual(StatusForbidden, Response.StatusCode);
  Assert.IsEmpty(Response.Location);
end;

procedure TAccountControllerTests.LinkKeepsTheSession;
begin
  const SessionCookie = SignInAs(FirstObjectId, 'Test User', 'user@example.test');
  const UserId = UserIdOf(SessionCookie);
  const LoginCookie = StartLinking(SessionCookie);

  FProvider.SetIdentity(TenantId, SecondObjectId, 'Second Account', 'second@example.test');
  const Callback = FRouter.Dispatch(CallbackRequest(LoginCookie, SessionCookie));

  Assert.AreEqual(StatusFound, Callback.StatusCode, Callback.Body);
  Assert.AreEqual('/account', Callback.Location);
  Assert.IsEmpty(SetCookieNamed(Callback, SessionCookieName), 'no new session');
  Assert.IsTrue(IsSessionStored(SessionCookie), 'the session that started linking stays');
  Assert.AreEqual<Integer>(2, CountAccounts(UserId));
end;

procedure TAccountControllerTests.LinkCallbackFromOtherBrowserDoesNotLink;
begin
  const VictimCookie = SignInAs(FirstObjectId, 'Victim', 'victim@example.test');
  const VictimId = UserIdOf(VictimCookie);
  const AttackerCookie = SignInAs(OtherObjectId, 'Attacker', 'attacker@example.test');
  const AttackerId = UserIdOf(AttackerCookie);
  StartLinking(AttackerCookie);

  // The victim opens the upstream URL of the attacker; the callback arrives in the browser of the victim,
  // which has its own session but not the login cookie of the attacker.
  const Callback = FRouter.Dispatch(CallbackRequest('', VictimCookie));

  Assert.AreEqual(StatusForbidden, Callback.StatusCode, Callback.Body);
  Assert.IsEmpty(Callback.Location);
  Assert.IsEmpty(SetCookieNamed(Callback, SessionCookieName), 'no session handed out');
  Assert.AreEqual<Integer>(1, CountAccounts(AttackerId), 'the victim account is not linked to the attacker');
  Assert.AreEqual<Integer>(1, CountAccounts(VictimId), 'the victim account stays with the victim');
  Assert.IsTrue(IsSessionStored(VictimCookie), 'the victim session stays');
end;

procedure TAccountControllerTests.LinkCallbackWithOtherSessionUserIsRejected;
begin
  const VictimCookie = SignInAs(FirstObjectId, 'Victim', 'victim@example.test');
  const AttackerCookie = SignInAs(OtherObjectId, 'Attacker', 'attacker@example.test');
  const AttackerId = UserIdOf(AttackerCookie);
  const AttackerLoginCookie = StartLinking(AttackerCookie);

  // Even with the login cookie of the attacker, a link only completes in the session that started it.
  const Callback = FRouter.Dispatch(CallbackRequest(AttackerLoginCookie, VictimCookie));

  Assert.AreEqual(StatusForbidden, Callback.StatusCode, Callback.Body);
  Assert.IsEmpty(Callback.Location);
  Assert.AreEqual<Integer>(1, CountAccounts(AttackerId), 'the victim account is not linked to the attacker');
end;

procedure TAccountControllerTests.LinkingAccountOfOtherUserCompletes;
begin
  const OwnerCookie = SignInAs(FirstObjectId, 'Owner', 'owner@example.test');
  const OwnerId = UserIdOf(OwnerCookie);
  const OtherCookie = SignInAs(OtherObjectId, 'Colleague', 'colleague@example.test');
  const OtherId = UserIdOf(OtherCookie);
  const LoginCookie = StartLinking(OtherCookie);

  FProvider.SetIdentity(TenantId, FirstObjectId, 'Owner', 'owner@example.test');
  const Callback = FRouter.Dispatch(CallbackRequest(LoginCookie, OtherCookie));

  Assert.AreEqual(StatusFound, Callback.StatusCode, Callback.Body);
  Assert.AreEqual('/account', Callback.Location);
  Assert.AreEqual<Integer>(2, CountAccounts(OtherId), 'linked for the colleague');
  Assert.AreEqual<Integer>(1, CountAccounts(OwnerId), 'the owner keeps his own link');
end;

procedure TAccountControllerTests.AccountPageShowsTheSignInAccount;
begin
  const SessionCookie = SignInAs(FirstObjectId, 'Test User', 'alice@example.test');
  AddAccount(UserIdOf(SessionCookie), SecondObjectId, 'Shared Mailbox');

  const Response = FRouter.Dispatch(NewRequest('GET', '/account', '', '', SessionCookie));

  Assert.AreEqual(StatusOk, Response.StatusCode, Response.Body);
  Assert.Contains(Response.Body, 'Signed in as <strong>Test User</strong> with <strong>alice@example.test</strong>');
  Assert.Contains(Response.Body, SecondObjectId + '@example.test');
end;

procedure TAccountControllerTests.AccountPageWithoutSignInAccountOmitsIt;
begin
  var User := Default(TAuthUser);
  User.Id           := 'user-without-identity';
  User.DisplayName  := 'Lone User';
  User.CreatedAtUtc := FClock.NowUtc;
  FStores.Users.Save(User);
  var SetCookie: string;
  FSessions.Start(User.Id, SetCookie);

  const Response = FRouter.Dispatch(NewRequest('GET', '/account', '', '', CookieValue(SetCookie)));

  Assert.AreEqual(StatusOk, Response.StatusCode, Response.Body);
  Assert.Contains(Response.Body, 'Signed in as <strong>Lone User</strong>. Here you choose');
end;

procedure TAccountControllerTests.PostsWithoutSessionAreRejected;
begin
  for var Path in ['/account/link', '/account/reconnect', '/account/unlink', '/account/revoke', '/logout'] do
  begin
    const Response = PostForm(Path, 'key=x&family=x&provider=fake&csrf=x', '');

    Assert.AreEqual(StatusForbidden, Response.StatusCode, Path);
    Assert.IsEmpty(Response.Location, Path);
  end;
end;

procedure TAccountControllerTests.LoginWithOneProviderGoesStraightToIt;
begin
  const Response = FRouter.Dispatch(NewRequest('GET', '/login', '', '', ''));

  Assert.AreEqual(StatusFound, Response.StatusCode, Response.Body);
  Assert.StartsWith(UpstreamLoginPrefix, Response.Location);
end;

procedure TAccountControllerTests.LoginWithSeveralProvidersShowsChoice;
begin
  FreeHosts;
  const SecondProvider: IUpstreamProvider = TFakeUpstreamProvider.Create(OtherProviderName);
  BuildHosts([FProviderReference, SecondProvider]);

  const Response = FRouter.Dispatch(NewRequest('GET', '/login', '', '', ''));

  Assert.AreEqual(StatusOk, Response.StatusCode, Response.Body);
  Assert.StartsWith('text/html', Response.ContentType);
  Assert.IsEmpty(Response.Location);
  Assert.Contains(Response.Body, 'value="fake"');
  Assert.Contains(Response.Body, 'value="other"');
end;

procedure TAccountControllerTests.LoginWithChosenProviderRedirectsToIt;
begin
  FreeHosts;
  const SecondProvider: IUpstreamProvider = TFakeUpstreamProvider.Create(OtherProviderName);
  BuildHosts([FProviderReference, SecondProvider]);

  const Response = FRouter.Dispatch(NewRequest('GET', '/login', 'provider=other', '', ''));

  Assert.AreEqual(StatusFound, Response.StatusCode, Response.Body);
  Assert.StartsWith(UpstreamLoginPrefix, Response.Location);
end;

procedure TAccountControllerTests.LoginWithUnknownProviderShowsError;
begin
  const Response = FRouter.Dispatch(NewRequest('GET', '/login', 'provider=unknown', '', ''));

  Assert.AreEqual(StatusBadRequest, Response.StatusCode, Response.Body);
  Assert.IsEmpty(Response.Location);
end;

procedure TAccountControllerTests.LogoutRequiresCsrf;
begin
  const SessionCookie = SignInAs(FirstObjectId, 'Test User', 'user@example.test');

  const Response = PostForm('/logout', 'csrf=wrong', SessionCookie);

  Assert.AreEqual(StatusForbidden, Response.StatusCode);
  Assert.IsTrue(IsSessionStored(SessionCookie), 'session kept');
end;

procedure TAccountControllerTests.LogoutEndsTheSession;
begin
  const SessionCookie = SignInAs(FirstObjectId, 'Test User', 'user@example.test');

  const Response = PostForm('/logout', Format('csrf=%s', [TNetEncoding.URL.EncodeForm(CsrfOf(SessionCookie))]), SessionCookie);

  Assert.AreEqual(StatusOk, Response.StatusCode, Response.Body);
  Assert.AreEqual<Integer>(1, Length(Response.SetCookies), 'one clearing cookie');
  Assert.Contains(Response.SetCookies[0], 'Max-Age=0');
  Assert.IsFalse(IsSessionStored(SessionCookie), 'session removed from the store');
end;

procedure TAccountControllerTests.InternalRoutesAreNotOnPublicRouter;
begin
  for var Path in ['/internal/introspect', '/internal/accounts', '/internal/upstream-token'] do
  begin
    const Response = PostForm(Path, 'token=x', '');

    Assert.AreEqual(StatusNotFound, Response.StatusCode, Path);
    Assert.IsEmpty(Response.Location, Path);
  end;
end;

end.
