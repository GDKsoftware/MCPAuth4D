unit MCPAuth.Client.Tests;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  MCPServer.Authorization,
  MCPAuth.Fakes.Clock,
  MCPAuth.Fakes.UpstreamProvider,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Store.Interfaces,
  MCPAuth.Upstream.Interfaces,
  MCPAuth.Identity.Interfaces,
  MCPAuth.OAuth.Types,
  MCPAuth.Web.Router,
  MCPAuth.Internal.Controller,
  MCPAuth.Web.Server.Indy,
  MCPAuth.Client.UpstreamAccounts.Interfaces;

type
  [TestFixture]
  TClientTests = class
  private
    FClock: TFakeClock;
    FClockReference: IClock;
    FStores: TStoreSet;
    FProvider: TFakeUpstreamProvider;
    FProviderReference: IUpstreamProvider;
    FAccounts: ILinkedAccounts;
    FController: TInternalController;
    FInternalRouter: TWebRouter;
    FFrontRouter: TWebRouter;
    FServer: TMCPAuthWebServer;
    FIntrospectCount: Integer;
    FUpstreamTokenCount: Integer;

    function BuildResourceRegistryJson: string;
    function BaseUrl: string;
    function AuthorizerFor(const Resource, ServiceSecret: string; const CacheSeconds: Integer = 60): IMCPAuthorizer;
    function RemoteAccounts(const ServiceSecret: string = 'secret-a'): IUpstreamAccounts;
    function Authorize(const Authorizer: IMCPAuthorizer; const Token: string): TMCPAuthResult;
    procedure CountAndForward(const Path: string);
    procedure SaveToken(const Token, UserId, Resource: string);
    function LinkFakeAccount(const UserId, ObjectId: string): string;
    procedure EnsureUser(const UserId: string);

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure AuthorizerAllowsTokenOfOwnResourceWithUserAsSubject;

    [Test]
    procedure AuthorizerRejectsTokenOfOtherResource;

    [Test]
    procedure AuthorizerCachesPositiveResult;

    [Test]
    procedure AuthorizerCacheEndsAfterCacheSeconds;

    [Test]
    procedure AuthorizerDoesNotCacheNegativeResult;

    [Test]
    procedure WrongServiceSecretFailsClosed;

    [Test]
    procedure AccountPageUrlAppendsAccountToIssuer;

    [Test]
    procedure ListForUserReturnsAccounts;

    [Test]
    procedure GetAccessTokenReturnsTokenAndCachesIt;

    [Test]
    procedure GetAccessTokenFetchesAgainWithinAMinuteOfExpiry;

    [Test]
    procedure GetAccessTokenMapsUnknownAccountToNotFound;

    [Test]
    procedure GetAccessTokenMaps409ToNeedsReconnect;

    [Test]
    procedure GetAccessTokenMaps403ToForbidden;

    [Test]
    procedure WrongServiceSecretRaisesAccountsErrorWithoutSecret;

    [Test]
    procedure UnreachableAuthServerRaisesAccountsError;
  end;

implementation

uses
  System.DateUtils,
  System.StrUtils,
  System.SyncObjs,
  System.NetEncoding,
  Spring.Collections,
  MCPAuth.Secret.Hash,
  MCPAuth.Secret.KeyRing,
  MCPAuth.Secret.AesGcm,
  MCPAuth.Store.Memory,
  MCPAuth.Identity.Types,
  MCPAuth.Identity.Accounts,
  MCPAuth.Identity.Access.AllowAll,
  MCPAuth.Resource.Registry.Json,
  MCPAuth.Upstream.Providers,
  MCPAuth.Web.Types,
  MCPAuth.Client,
  MCPAuth.Client.Authorizer,
  MCPAuth.Client.UpstreamAccounts,
  MCPAuth.Client.UpstreamAccounts.Exceptions;

const
  ResourceA = 'https://a.example.test/mcp';
  ResourceB = 'https://b.example.test/mcp';
  ServiceSecretA = 'secret-a';
  ServiceSecretB = 'secret-b';
  FakeProviderName = 'fake';
  TenantId = 'tenant-1';
  KeyId = 'k1';
  KeyLength = 32;
  UserOne = 'user-1';
  AccessTokenValue = 'access-token-1';
  GrantedScopes = 'openid offline_access read';
  Loopback = '127.0.0.1';
  IntrospectPath = '/internal/introspect';
  UpstreamTokenPath = '/internal/upstream-token';
  PostMethod = 'POST';
  OneMinuteInSeconds = 60;
  SecsPerHour = 3600;

{ TClientTests }

procedure TClientTests.Setup;
begin
  FIntrospectCount := 0;
  FUpstreamTokenCount := 0;
  FClock := TFakeClock.Create(TTimeZone.Local.ToUniversalTime(Now));
  FClockReference := FClock;
  FStores := TMemoryStore.CreateSet(FClockReference);
  FProvider := TFakeUpstreamProvider.Create(FakeProviderName);
  FProviderReference := FProvider;
  FProvider.Scope := GrantedScopes;
  FProvider.ExpiresAtUtc := IncHour(FClock.NowUtc, 1);

  var Key: TBytes;
  SetLength(Key, KeyLength);
  FillChar(Key[0], KeyLength, 5);
  const Keys = TCollections.CreateDictionary<string, TBytes>;
  Keys[KeyId] := Key;
  const Protector = TAesGcmProtector.Create(TKeyRing.Create(KeyId, Keys));
  const Providers = TUpstreamProviders.Create([FProviderReference]);

  FAccounts := TLinkedAccounts.Create(FStores.Users, FStores.LinkedAccounts, Protector, TAllowAllAccessPolicy.Create, Providers, FClockReference);
  FController := TInternalController.Create(TJsonResourceRegistry.FromJson(BuildResourceRegistryJson), FStores.Tokens, FAccounts);
  FInternalRouter := TWebRouter.Create;
  FController.Register(FInternalRouter);

  // Every request passes this front router, so the tests can count the HTTP calls that reach the auth server.
  FFrontRouter := TWebRouter.Create;
  FFrontRouter.AddPrefix(PostMethod, '/',
    function(const Request: TWebRequest): TWebResponse
    begin
      CountAndForward(Request.Path);
      Result := FInternalRouter.Dispatch(Request);
    end);

  FServer := TMCPAuthWebServer.Create(FFrontRouter, 0, Loopback);
  FServer.Start;
end;

procedure TClientTests.TearDown;
begin
  FServer.Free;
  FFrontRouter.Free;
  FInternalRouter.Free;
  FController.Free;
  FAccounts := nil;
  FProviderReference := nil;
  FStores := Default(TStoreSet);
  FClockReference := nil;
end;

procedure TClientTests.CountAndForward(const Path: string);
begin
  if Path = IntrospectPath then
    TInterlocked.Increment(FIntrospectCount);
  if Path = UpstreamTokenPath then
    TInterlocked.Increment(FUpstreamTokenCount);
end;

function TClientTests.BuildResourceRegistryJson: string;
begin
  const Entry = '{"resource":"%s","name":"%s","service_id":"%s","service_secret_sha256":"%s","providers":[{"provider":"fake","scopes":["read"]}]}';

  const EntryA = Format(Entry, [ResourceA, 'Resource A', 'service-a', TTokenHash.Of(ServiceSecretA)]);
  const EntryB = Format(Entry, [ResourceB, 'Resource B', 'service-b', TTokenHash.Of(ServiceSecretB)]);
  Result := Format('{"resources":[%s,%s]}', [EntryA, EntryB]);
end;

function TClientTests.BaseUrl: string;
begin
  Result := Format('http://%s:%d', [Loopback, FServer.BoundPort]);
end;

function TClientTests.AuthorizerFor(const Resource, ServiceSecret: string; const CacheSeconds: Integer): IMCPAuthorizer;
begin
  const ServiceId = IfThen(Resource = ResourceA, 'service-a', 'service-b');

  Result := TMCPAuthClient.CreateAuthorizer(Resource, BaseUrl, ServiceId, ServiceSecret, CacheSeconds);
end;

function TClientTests.RemoteAccounts(const ServiceSecret: string): IUpstreamAccounts;
begin
  Result := TRemoteUpstreamAccounts.Create(BaseUrl, 'service-a', ServiceSecret);
end;

function TClientTests.Authorize(const Authorizer: IMCPAuthorizer; const Token: string): TMCPAuthResult;
begin
  Result := Authorizer.Authorize(Token, 'POST', '/mcp');
end;

procedure TClientTests.SaveToken(const Token, UserId, Resource: string);
begin
  var Issued := Default(TIssuedToken);
  Issued.Hash         := TTokenHash.Of(Token);
  Issued.Kind         := TTokenKind.Access;
  Issued.FamilyId     := 'family-' + UserId + Resource;
  Issued.UserId       := UserId;
  Issued.ClientId     := 'client-1';
  Issued.Scope        := 'mcp';
  Issued.Resource     := Resource;
  Issued.CreatedAtUtc := FClock.NowUtc;
  Issued.ExpiresAtUtc := IncHour(FClock.NowUtc, 1);
  FStores.Tokens.Save(Issued);
end;

procedure TClientTests.EnsureUser(const UserId: string);
begin
  var User := Default(TAuthUser);
  User.Id := UserId;
  User.DisplayName := 'User ' + UserId;
  User.CreatedAtUtc := FClock.NowUtc;
  FStores.Users.Save(User);
end;

function TClientTests.LinkFakeAccount(const UserId, ObjectId: string): string;
begin
  EnsureUser(UserId);
  FProvider.SetIdentity(TenantId, ObjectId, 'Display ' + ObjectId, ObjectId + '@example.test');
  const Tokens = FProvider.Refresh(FProvider.RefreshToken);
  Result := FAccounts.Link(UserId, Tokens).Key.Value;
end;

procedure TClientTests.AuthorizerAllowsTokenOfOwnResourceWithUserAsSubject;
begin
  SaveToken(AccessTokenValue, UserOne, ResourceA);
  const Authorizer = AuthorizerFor(ResourceA, ServiceSecretA);

  const Outcome = Authorize(Authorizer, AccessTokenValue);

  Assert.AreEqual<TMCPAuthDecision>(TMCPAuthDecision.Allow, Outcome.Decision);
  Assert.AreEqual(UserOne, Outcome.Principal.Subject);
  Assert.IsTrue(Outcome.Principal.HasScope('mcp'));
end;

procedure TClientTests.AuthorizerRejectsTokenOfOtherResource;
begin
  SaveToken(AccessTokenValue, UserOne, ResourceB);
  const Authorizer = AuthorizerFor(ResourceA, ServiceSecretA);

  const Outcome = Authorize(Authorizer, AccessTokenValue);

  Assert.AreEqual<TMCPAuthDecision>(TMCPAuthDecision.Unauthorized, Outcome.Decision);
end;

procedure TClientTests.AuthorizerCachesPositiveResult;
begin
  SaveToken(AccessTokenValue, UserOne, ResourceA);
  const Authorizer = AuthorizerFor(ResourceA, ServiceSecretA);

  const First = Authorize(Authorizer, AccessTokenValue);
  const Second = Authorize(Authorizer, AccessTokenValue);

  Assert.AreEqual<TMCPAuthDecision>(TMCPAuthDecision.Allow, First.Decision);
  Assert.AreEqual<TMCPAuthDecision>(TMCPAuthDecision.Allow, Second.Decision);
  Assert.AreEqual(UserOne, Second.Principal.Subject);
  Assert.AreEqual(1, FIntrospectCount, 'the second call must not reach the auth server');
end;

procedure TClientTests.AuthorizerCacheEndsAfterCacheSeconds;
begin
  SaveToken(AccessTokenValue, UserOne, ResourceA);
  const CacheClock = TFakeClock.Create(FClock.NowUtc);
  const CacheClockReference: IClock = CacheClock;
  const Authorizer: IMCPAuthorizer = TCachingAuthorizer.Create(ResourceA, BaseUrl + IntrospectPath, 'service-a', ServiceSecretA, OneMinuteInSeconds, CacheClockReference);

  Authorize(Authorizer, AccessTokenValue);
  CacheClock.AdvanceSeconds(OneMinuteInSeconds - 1);
  Authorize(Authorizer, AccessTokenValue);
  CacheClock.AdvanceSeconds(2);
  const Third = Authorize(Authorizer, AccessTokenValue);

  Assert.AreEqual<TMCPAuthDecision>(TMCPAuthDecision.Allow, Third.Decision);
  Assert.AreEqual(2, FIntrospectCount, 'one call inside the period is cached, the one after it is not');
end;

procedure TClientTests.AuthorizerDoesNotCacheNegativeResult;
begin
  const Authorizer = AuthorizerFor(ResourceA, ServiceSecretA);

  const First = Authorize(Authorizer, AccessTokenValue);
  const Second = Authorize(Authorizer, AccessTokenValue);
  SaveToken(AccessTokenValue, UserOne, ResourceA);
  const Third = Authorize(Authorizer, AccessTokenValue);

  Assert.AreEqual<TMCPAuthDecision>(TMCPAuthDecision.Unauthorized, First.Decision);
  Assert.AreEqual<TMCPAuthDecision>(TMCPAuthDecision.Unauthorized, Second.Decision);
  Assert.AreEqual<TMCPAuthDecision>(TMCPAuthDecision.Allow, Third.Decision);
  Assert.AreEqual(3, FIntrospectCount);
end;

procedure TClientTests.WrongServiceSecretFailsClosed;
begin
  SaveToken(AccessTokenValue, UserOne, ResourceA);
  const Authorizer = AuthorizerFor(ResourceA, 'wrong-secret');

  const Outcome = Authorize(Authorizer, AccessTokenValue);

  Assert.AreEqual<TMCPAuthDecision>(TMCPAuthDecision.Unauthorized, Outcome.Decision);
end;

procedure TClientTests.AccountPageUrlAppendsAccountToIssuer;
begin
  Assert.AreEqual('https://auth.example.test/account', TMCPAuthClient.AccountPageUrl('https://auth.example.test'));
  Assert.AreEqual('https://auth.example.test/account', TMCPAuthClient.AccountPageUrl('https://auth.example.test/'));
end;

procedure TClientTests.ListForUserReturnsAccounts;
begin
  const Key = LinkFakeAccount(UserOne, 'object-1');

  const Accounts = RemoteAccounts.ListForUser(UserOne);

  Assert.AreEqual(1, Integer(Length(Accounts)));
  Assert.AreEqual(Key, Accounts[0].Key);
  Assert.AreEqual(FakeProviderName, Accounts[0].Provider);
  Assert.AreEqual('Display object-1', Accounts[0].DisplayName);
  Assert.AreEqual('object-1@example.test', Accounts[0].UserName);
  Assert.IsFalse(Accounts[0].NeedsReconnect);
end;

procedure TClientTests.GetAccessTokenReturnsTokenAndCachesIt;
begin
  const Key = LinkFakeAccount(UserOne, 'object-1');
  SaveToken(AccessTokenValue, UserOne, ResourceA);
  const Remote = RemoteAccounts;

  const First = Remote.GetAccessToken(UserOne, Key);
  const Second = Remote.GetAccessToken(UserOne, Key);

  Assert.IsNotEmpty(First);
  Assert.AreEqual(First, Second);
  Assert.AreEqual(1, FUpstreamTokenCount, 'the second call comes from the cache');
end;

procedure TClientTests.GetAccessTokenFetchesAgainWithinAMinuteOfExpiry;
begin
  const Key = LinkFakeAccount(UserOne, 'object-1');
  SaveToken(AccessTokenValue, UserOne, ResourceA);
  const RemoteClock = TFakeClock.Create(FClock.NowUtc);
  const RemoteClockReference: IClock = RemoteClock;
  const Remote: IUpstreamAccounts = TRemoteUpstreamAccounts.Create(BaseUrl, 'service-a', ServiceSecretA, RemoteClockReference);

  Remote.GetAccessToken(UserOne, Key);
  RemoteClock.AdvanceSeconds(SecsPerHour - OneMinuteInSeconds - 1);
  Remote.GetAccessToken(UserOne, Key);
  RemoteClock.AdvanceSeconds(2);
  Remote.GetAccessToken(UserOne, Key);

  Assert.AreEqual(2, FUpstreamTokenCount, 'cached until 60 seconds before it expires');
end;

procedure TClientTests.GetAccessTokenMapsUnknownAccountToNotFound;
begin
  EnsureUser(UserOne);
  SaveToken(AccessTokenValue, UserOne, ResourceA);
  const Remote = RemoteAccounts;

  Assert.WillRaise(
    procedure
    begin
      Remote.GetAccessToken(UserOne, 'fake:tenant-1:unknown');
    end,
    EUpstreamAccountNotFound);
end;

procedure TClientTests.GetAccessTokenMaps409ToNeedsReconnect;
begin
  const Key = LinkFakeAccount(UserOne, 'object-1');
  FProvider.IsRevoked := True;
  FClock.AdvanceSeconds(2 * SecsPerHour);
  SaveToken(AccessTokenValue, UserOne, ResourceA);
  const Remote = RemoteAccounts;

  try
    Remote.GetAccessToken(UserOne, Key);
    Assert.Fail('EUpstreamAccountNeedsReconnect expected');
  except
    on E: EUpstreamAccountNeedsReconnect do
      Assert.AreEqual('revoked', E.Reason);
  end;
end;

procedure TClientTests.GetAccessTokenMaps403ToForbidden;
begin
  const Key = LinkFakeAccount(UserOne, 'object-1');
  const Remote = RemoteAccounts;

  Assert.WillRaise(
    procedure
    begin
      Remote.GetAccessToken(UserOne, Key);
    end,
    EUpstreamAccessForbidden);
end;

procedure TClientTests.WrongServiceSecretRaisesAccountsErrorWithoutSecret;
begin
  const Remote = RemoteAccounts('wrong-secret');

  try
    Remote.ListForUser(UserOne);
    Assert.Fail('EUpstreamAccountsError expected');
  except
    on E: EUpstreamAccountsError do
      Assert.IsFalse(E.Message.Contains('wrong-secret'));
  end;
end;

procedure TClientTests.UnreachableAuthServerRaisesAccountsError;
begin
  const Remote: IUpstreamAccounts = TRemoteUpstreamAccounts.Create('http://127.0.0.1:1', 'service-a', ServiceSecretA);

  Assert.WillRaise(
    procedure
    begin
      Remote.ListForUser(UserOne);
    end,
    EUpstreamAccountsError);
end;

end.
