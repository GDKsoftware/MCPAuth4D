unit MCPAuth.Internal.Controller.Tests;

interface

uses
  System.SysUtils,
  System.JSON,
  DUnitX.TestFramework,
  MCPAuth.Fakes.Clock,
  MCPAuth.Fakes.UpstreamProvider,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Store.Interfaces,
  MCPAuth.Upstream.Interfaces,
  MCPAuth.Identity.Interfaces,
  MCPAuth.OAuth.Types,
  MCPAuth.Web.Types,
  MCPAuth.Web.Router,
  MCPAuth.Internal.Controller;

type
  [TestFixture]
  TInternalControllerTests = class
  private
    FClock: TFakeClock;
    FClockReference: IClock;
    FStores: TStoreSet;
    FProvider: TFakeUpstreamProvider;
    FProviderReference: IUpstreamProvider;
    FOtherProvider: IUpstreamProvider;
    FAccounts: ILinkedAccounts;
    FController: TInternalController;
    FRouter: TWebRouter;

    function BuildResourceRegistryJson: string;
    function BasicHeader(const ServiceId, Secret: string): string;
    function NewRequest(const Path, Body, AuthorizationHeader: string): TWebRequest;
    function CallAsA(const Path, Body: string): TWebResponse;
    function CallAsB(const Path, Body: string): TWebResponse;
    procedure SaveToken(const Token, UserId, Resource: string; const Kind: TTokenKind);
    function LinkFakeAccount(const UserId, ObjectId: string): string;
    function LinkOtherAccount(const UserId: string): string;
    procedure EnsureUser(const UserId: string);
    function HeaderValue(const Response: TWebResponse; const Name: string): string;
    function JsonOf(const Response: TWebResponse): TJSONObject;

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure IntrospectionWithoutServiceAuthIs401;

    [Test]
    procedure WrongServiceSecretIs401WithoutDetail;

    [Test]
    procedure IntrospectionOfOwnResourcesTokenIsActive;

    [Test]
    procedure IntrospectionOfOtherResourcesTokenIsInactive;

    [Test]
    procedure IntrospectionOfRefreshTokenIsInactive;

    [Test]
    procedure IntrospectionOfUnknownOrExpiredTokenIsInactive;

    [Test]
    procedure AccountsAreFilteredByResourceProviders;

    [Test]
    procedure AccountsOfUserWithoutLinkedAccountsAreEmpty;

    [Test]
    procedure AccountsForResourceWithoutConsentAreForbidden;

    [Test]
    procedure UpstreamTokenReturnsAccessToken;

    [Test]
    procedure UpstreamTokenForListedKeyWithColonsInObjectIdReturnsAccessToken;

    [Test]
    procedure UpstreamTokenForResourceWithoutConsentIsForbidden;

    [Test]
    procedure UpstreamTokenForProviderOfOtherResourceIsForbidden;

    [Test]
    procedure UpstreamTokenForUnknownAccountIsNotFound;

    [Test]
    procedure UpstreamTokenForAccountOfOtherUserIsNotFound;

    [Test]
    procedure UpstreamTokenNeedingReconnectIs409WithReason;

    [Test]
    procedure UpstreamTokenAfterRevocationIs409Revoked;

    [Test]
    procedure MalformedBodyIs400;

    [Test]
    procedure EveryResponseIsJsonWithNoStore;

    [Test]
    procedure UnknownPathIsJson404;
  end;

implementation

uses
  System.Generics.Collections,
  System.DateUtils,
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
  MCPAuth.Upstream.Types,
  MCPAuth.Upstream.Providers;

const
  ResourceA = 'https://a.example.test/mcp';
  ResourceB = 'https://b.example.test/mcp';
  ServiceSecretA = 'secret-a';
  ServiceSecretB = 'secret-b';
  FakeProviderName = 'fake';
  OtherProviderName = 'other';
  TenantId = 'tenant-1';
  KeyId = 'k1';
  KeyLength = 32;
  UserOne = 'user-1';
  UserTwo = 'user-2';
  ObjectIdWithColons = 'f:Realm:Carol';
  AccessTokenValue = 'access-token-1';
  RefreshTokenValue = 'refresh-token-1';
  StatusOk = 200;
  StatusBadRequest = 400;
  StatusUnauthorized = 401;
  StatusForbidden = 403;
  StatusNotFound = 404;
  StatusConflict = 409;
  GrantedScopes = 'openid offline_access read';
  InactiveBody = '{"active":false}';
  OneHourInSeconds = 3600;

{ TInternalControllerTests }

procedure TInternalControllerTests.Setup;
begin
  FClock := TFakeClock.Create(EncodeDateTime(2026, 1, 2, 3, 4, 5, 0));
  FClockReference := FClock;
  FStores := TMemoryStore.CreateSet(FClockReference);
  FProvider := TFakeUpstreamProvider.Create(FakeProviderName);
  FProviderReference := FProvider;
  FProvider.Scope := GrantedScopes;
  FProvider.ExpiresAtUtc := IncHour(FClock.NowUtc, 1);
  FOtherProvider := TFakeUpstreamProvider.Create(OtherProviderName);

  var Key: TBytes;
  SetLength(Key, KeyLength);
  FillChar(Key[0], KeyLength, 5);
  const Keys = TCollections.CreateDictionary<string, TBytes>;
  Keys[KeyId] := Key;
  const Protector = TAesGcmProtector.Create(TKeyRing.Create(KeyId, Keys));
  const Providers = TUpstreamProviders.Create([FProviderReference, FOtherProvider]);

  FAccounts := TLinkedAccounts.Create(FStores.Users, FStores.LinkedAccounts, Protector, TAllowAllAccessPolicy.Create, Providers, FClockReference);
  FController := TInternalController.Create(TJsonResourceRegistry.FromJson(BuildResourceRegistryJson), FStores.Tokens, FAccounts);
  FRouter := TWebRouter.Create;
  FController.Register(FRouter);
end;

procedure TInternalControllerTests.TearDown;
begin
  FRouter.Free;
  FController.Free;
  FAccounts := nil;
  FOtherProvider := nil;
  FProviderReference := nil;
  FStores := Default(TStoreSet);
  FClockReference := nil;
end;

function TInternalControllerTests.BuildResourceRegistryJson: string;
begin
  const Entry = '{"resource":"%s","name":"%s","service_id":"%s","service_secret_sha256":"%s","providers":[%s]}';
  const FakeEntry = '{"provider":"fake","scopes":["read"]}';
  const OtherEntry = '{"provider":"other","scopes":["write"]}';

  const EntryA = Format(Entry, [ResourceA, 'Resource A', 'service-a', TTokenHash.Of(ServiceSecretA), FakeEntry]);
  const EntryB = Format(Entry, [ResourceB, 'Resource B', 'service-b', TTokenHash.Of(ServiceSecretB), FakeEntry + ',' + OtherEntry]);
  Result := Format('{"resources":[%s,%s]}', [EntryA, EntryB]);
end;

function TInternalControllerTests.BasicHeader(const ServiceId, Secret: string): string;
begin
  const Credentials = TEncoding.UTF8.GetBytes(Format('%s:%s', [ServiceId, Secret]));
  Result := 'Basic ' + TNetEncoding.Base64.EncodeBytesToString(Credentials);
end;

function TInternalControllerTests.NewRequest(const Path, Body, AuthorizationHeader: string): TWebRequest;
begin
  Result := Default(TWebRequest);
  Result.Method        := 'POST';
  Result.Path          := Path;
  Result.Body          := Body;
  Result.RemoteAddress := '127.0.0.1';
  Result.Headers       := TCollections.CreateDictionary<string, string>;
  if not AuthorizationHeader.IsEmpty then
    Result.Headers['Authorization'] := AuthorizationHeader;
end;

function TInternalControllerTests.CallAsA(const Path, Body: string): TWebResponse;
begin
  Result := FRouter.Dispatch(NewRequest(Path, Body, BasicHeader('service-a', ServiceSecretA)));
end;

function TInternalControllerTests.CallAsB(const Path, Body: string): TWebResponse;
begin
  Result := FRouter.Dispatch(NewRequest(Path, Body, BasicHeader('service-b', ServiceSecretB)));
end;

procedure TInternalControllerTests.SaveToken(const Token, UserId, Resource: string; const Kind: TTokenKind);
begin
  var Issued := Default(TIssuedToken);
  Issued.Hash         := TTokenHash.Of(Token);
  Issued.Kind         := Kind;
  Issued.FamilyId     := 'family-' + UserId + Resource;
  Issued.UserId       := UserId;
  Issued.ClientId     := 'client-1';
  Issued.Scope        := 'mcp';
  Issued.Resource     := Resource;
  Issued.CreatedAtUtc := FClock.NowUtc;
  Issued.ExpiresAtUtc := IncHour(FClock.NowUtc, 1);
  FStores.Tokens.Save(Issued);
end;

procedure TInternalControllerTests.EnsureUser(const UserId: string);
begin
  var User := Default(TAuthUser);
  User.Id := UserId;
  User.DisplayName := 'User ' + UserId;
  User.CreatedAtUtc := FClock.NowUtc;
  FStores.Users.Save(User);
end;

function TInternalControllerTests.LinkFakeAccount(const UserId, ObjectId: string): string;
begin
  EnsureUser(UserId);
  FProvider.SetIdentity(TenantId, ObjectId, 'Display ' + ObjectId, ObjectId + '@example.test');
  const Tokens = FProvider.Refresh(FProvider.RefreshToken, []);
  Result := FAccounts.Link(UserId, Tokens).Key.Value;
end;

function TInternalControllerTests.LinkOtherAccount(const UserId: string): string;
begin
  EnsureUser(UserId);

  var Tokens := Default(TUpstreamTokens);
  Tokens.AccessToken := 'other-access';
  Tokens.RefreshToken := 'other-refresh';
  Tokens.Scope := 'write';
  Tokens.ExpiresAtUtc := IncHour(FClock.NowUtc, 1);
  Tokens.Identity.Key.Provider := OtherProviderName;
  Tokens.Identity.Key.TenantId := TenantId;
  Tokens.Identity.Key.ObjectId := 'object-x';
  Tokens.Identity.DisplayName := 'Other Account';
  Tokens.Identity.UserName := 'other@example.test';
  Result := FAccounts.Link(UserId, Tokens).Key.Value;
end;

function TInternalControllerTests.HeaderValue(const Response: TWebResponse; const Name: string): string;
begin
  for var Header in Response.ExtraHeaders do
  begin
    if SameText(Header.Key, Name) then
      Exit(Header.Value);
  end;

  Result := '';
end;

function TInternalControllerTests.JsonOf(const Response: TWebResponse): TJSONObject;
begin
  Result := TJSONObject.ParseJSONValue(Response.Body) as TJSONObject;
end;

procedure TInternalControllerTests.IntrospectionWithoutServiceAuthIs401;
begin
  SaveToken(AccessTokenValue, UserOne, ResourceA, TTokenKind.Access);

  const Response = FRouter.Dispatch(NewRequest('/internal/introspect', 'token=' + AccessTokenValue, ''));

  Assert.AreEqual(StatusUnauthorized, Response.StatusCode);
  Assert.IsFalse(Response.Body.Contains(AccessTokenValue));
  Assert.IsFalse(Response.Body.Contains('active'));
end;

procedure TInternalControllerTests.WrongServiceSecretIs401WithoutDetail;
begin
  const Request = NewRequest('/internal/accounts', '{"sub":"user-1"}', BasicHeader('service-a', 'wrong'));

  const Response = FRouter.Dispatch(Request);

  Assert.AreEqual(StatusUnauthorized, Response.StatusCode);
  Assert.AreEqual('{"error":"unauthorized"}', Response.Body);
end;

procedure TInternalControllerTests.IntrospectionOfOwnResourcesTokenIsActive;
begin
  SaveToken(AccessTokenValue, UserOne, ResourceA, TTokenKind.Access);

  const Response = CallAsA('/internal/introspect', 'token=' + AccessTokenValue);

  Assert.AreEqual(StatusOk, Response.StatusCode);
  const Json = JsonOf(Response);
  try
    Assert.IsTrue(Json.GetValue<Boolean>('active'));
    Assert.AreEqual(UserOne, Json.GetValue<string>('sub'));
    Assert.AreEqual('mcp', Json.GetValue<string>('scope'));
    Assert.AreEqual(ResourceA, Json.GetValue<string>('aud'));
    Assert.AreEqual('client-1', Json.GetValue<string>('client_id'));
    Assert.AreEqual('Bearer', Json.GetValue<string>('token_type'));
    Assert.AreEqual(DateTimeToUnix(IncHour(FClock.NowUtc, 1), True), Json.GetValue<Int64>('exp'));
  finally
    Json.Free;
  end;
end;

procedure TInternalControllerTests.IntrospectionOfOtherResourcesTokenIsInactive;
begin
  SaveToken(AccessTokenValue, UserOne, ResourceA, TTokenKind.Access);

  const Response = CallAsB('/internal/introspect', 'token=' + AccessTokenValue);

  Assert.AreEqual(StatusOk, Response.StatusCode);
  Assert.AreEqual(InactiveBody, Response.Body);
end;

procedure TInternalControllerTests.IntrospectionOfRefreshTokenIsInactive;
begin
  SaveToken(RefreshTokenValue, UserOne, ResourceA, TTokenKind.Refresh);

  const Response = CallAsA('/internal/introspect', 'token=' + RefreshTokenValue);

  Assert.AreEqual(InactiveBody, Response.Body);
end;

procedure TInternalControllerTests.IntrospectionOfUnknownOrExpiredTokenIsInactive;
begin
  SaveToken(AccessTokenValue, UserOne, ResourceA, TTokenKind.Access);
  FClock.SetNowUtc(IncHour(FClock.NowUtc, 2));

  const Expired = CallAsA('/internal/introspect', 'token=' + AccessTokenValue);
  const Unknown = CallAsA('/internal/introspect', 'token=nonsense');
  const Missing = CallAsA('/internal/introspect', '');

  Assert.AreEqual(InactiveBody, Expired.Body);
  Assert.AreEqual(InactiveBody, Unknown.Body);
  Assert.AreEqual(InactiveBody, Missing.Body);
end;

procedure TInternalControllerTests.AccountsAreFilteredByResourceProviders;
begin
  const FakeKey = LinkFakeAccount(UserOne, 'object-1');
  LinkOtherAccount(UserOne);
  SaveToken(AccessTokenValue, UserOne, ResourceA, TTokenKind.Access);
  SaveToken('access-token-b', UserOne, ResourceB, TTokenKind.Access);

  const ForA = CallAsA('/internal/accounts', '{"sub":"user-1"}');
  const ForB = CallAsB('/internal/accounts', '{"sub":"user-1"}');

  Assert.AreEqual(StatusOk, ForA.StatusCode);
  const JsonA = TJSONObject.ParseJSONValue(ForA.Body) as TJSONArray;
  const JsonB = TJSONObject.ParseJSONValue(ForB.Body) as TJSONArray;
  try
    Assert.AreEqual(1, JsonA.Count);
    const Account = JsonA.Items[0] as TJSONObject;
    Assert.AreEqual(FakeKey, Account.GetValue<string>('key'));
    Assert.AreEqual(FakeProviderName, Account.GetValue<string>('provider'));
    Assert.AreEqual('Display object-1', Account.GetValue<string>('display_name'));
    Assert.AreEqual('object-1@example.test', Account.GetValue<string>('user_name'));
    Assert.IsFalse(Account.GetValue<Boolean>('needs_reconnect'));
    Assert.AreEqual(2, JsonB.Count);
  finally
    JsonA.Free;
    JsonB.Free;
  end;
end;

procedure TInternalControllerTests.AccountsOfUserWithoutLinkedAccountsAreEmpty;
begin
  SaveToken(AccessTokenValue, 'nobody', ResourceA, TTokenKind.Access);

  const Response = CallAsA('/internal/accounts', '{"sub":"nobody"}');

  Assert.AreEqual(StatusOk, Response.StatusCode);
  Assert.AreEqual('[]', Response.Body);
end;

procedure TInternalControllerTests.AccountsForResourceWithoutConsentAreForbidden;
begin
  LinkFakeAccount(UserOne, 'object-1');
  SaveToken(AccessTokenValue, UserOne, ResourceA, TTokenKind.Access);

  const Response = CallAsB('/internal/accounts', '{"sub":"user-1"}');

  Assert.AreEqual(StatusForbidden, Response.StatusCode);
  Assert.AreEqual('{"error":"forbidden"}', Response.Body);
end;

procedure TInternalControllerTests.UpstreamTokenReturnsAccessToken;
begin
  const Key = LinkFakeAccount(UserOne, 'object-1');
  SaveToken(AccessTokenValue, UserOne, ResourceA, TTokenKind.Access);

  const Response = CallAsA('/internal/upstream-token', Format('{"sub":"user-1","account":"%s"}', [Key]));

  Assert.AreEqual(StatusOk, Response.StatusCode);
  const Json = JsonOf(Response);
  try
    Assert.IsTrue(Json.GetValue<string>('access_token').StartsWith('upstream-access'));
    Assert.AreEqual(DateTimeToUnix(IncHour(FClock.NowUtc, 1), True), Json.GetValue<Int64>('expires_at'));
  finally
    Json.Free;
  end;
end;

procedure TInternalControllerTests.UpstreamTokenForListedKeyWithColonsInObjectIdReturnsAccessToken;
begin
  LinkFakeAccount(UserOne, ObjectIdWithColons);
  SaveToken(AccessTokenValue, UserOne, ResourceA, TTokenKind.Access);
  const Listed = CallAsA('/internal/accounts', '{"sub":"user-1"}');
  const Accounts = TJSONObject.ParseJSONValue(Listed.Body) as TJSONArray;
  var Key: string;
  try
    const Account = Accounts.Items[0];
    Key := Account.GetValue<string>('key');
  finally
    Accounts.Free;
  end;

  const Response = CallAsA('/internal/upstream-token', Format('{"sub":"user-1","account":"%s"}', [Key]));

  Assert.AreEqual(Format('%s:%s:%s', [FakeProviderName, TenantId, ObjectIdWithColons]), Key, False);
  Assert.AreEqual(StatusOk, Response.StatusCode, Response.Body);
end;

procedure TInternalControllerTests.UpstreamTokenForResourceWithoutConsentIsForbidden;
begin
  const Key = LinkFakeAccount(UserOne, 'object-1');
  SaveToken(AccessTokenValue, UserOne, ResourceA, TTokenKind.Access);

  const Response = CallAsB('/internal/upstream-token', Format('{"sub":"user-1","account":"%s"}', [Key]));

  Assert.AreEqual(StatusForbidden, Response.StatusCode);
  Assert.AreEqual('{"error":"forbidden"}', Response.Body);
end;

procedure TInternalControllerTests.UpstreamTokenForProviderOfOtherResourceIsForbidden;
begin
  const Key = LinkOtherAccount(UserOne);
  SaveToken(AccessTokenValue, UserOne, ResourceA, TTokenKind.Access);

  const Response = CallAsA('/internal/upstream-token', Format('{"sub":"user-1","account":"%s"}', [Key]));

  Assert.AreEqual(StatusForbidden, Response.StatusCode);
  Assert.AreEqual('{"error":"forbidden"}', Response.Body);
end;

procedure TInternalControllerTests.UpstreamTokenForUnknownAccountIsNotFound;
begin
  LinkFakeAccount(UserOne, 'object-1');
  SaveToken(AccessTokenValue, UserOne, ResourceA, TTokenKind.Access);

  const Unknown = CallAsA('/internal/upstream-token', '{"sub":"user-1","account":"fake:tenant-1:nobody"}');
  const Malformed = CallAsA('/internal/upstream-token', '{"sub":"user-1","account":"garbage"}');

  Assert.AreEqual(StatusNotFound, Unknown.StatusCode);
  Assert.AreEqual('{"error":"account_not_found"}', Unknown.Body);
  Assert.AreEqual(StatusNotFound, Malformed.StatusCode);
end;

procedure TInternalControllerTests.UpstreamTokenForAccountOfOtherUserIsNotFound;
begin
  const Key = LinkFakeAccount(UserOne, 'object-1');
  EnsureUser(UserTwo);
  SaveToken(AccessTokenValue, UserTwo, ResourceA, TTokenKind.Access);

  const Response = CallAsA('/internal/upstream-token', Format('{"sub":"user-2","account":"%s"}', [Key]));

  Assert.AreEqual(StatusNotFound, Response.StatusCode);
  Assert.AreEqual('{"error":"account_not_found"}', Response.Body);
end;

procedure TInternalControllerTests.UpstreamTokenNeedingReconnectIs409WithReason;
begin
  FProvider.Scope := 'openid offline_access';
  const Key = LinkFakeAccount(UserOne, 'object-1');
  SaveToken(AccessTokenValue, UserOne, ResourceA, TTokenKind.Access);

  const Response = CallAsA('/internal/upstream-token', Format('{"sub":"user-1","account":"%s"}', [Key]));

  Assert.AreEqual(StatusConflict, Response.StatusCode);
  Assert.AreEqual('{"error":"reconnect_required","reason":"missing_scopes"}', Response.Body);
end;

procedure TInternalControllerTests.UpstreamTokenAfterRevocationIs409Revoked;
begin
  const Key = LinkFakeAccount(UserOne, 'object-1');
  FProvider.IsRevoked := True;
  FClock.SetNowUtc(IncHour(FClock.NowUtc, 2));
  SaveToken(AccessTokenValue, UserOne, ResourceA, TTokenKind.Access);

  const Response = CallAsA('/internal/upstream-token', Format('{"sub":"user-1","account":"%s"}', [Key]));

  Assert.AreEqual(StatusConflict, Response.StatusCode);
  Assert.AreEqual('{"error":"reconnect_required","reason":"revoked"}', Response.Body);
end;

procedure TInternalControllerTests.MalformedBodyIs400;
begin
  const NotJson = CallAsA('/internal/accounts', 'sub=user-1');
  const NoSub = CallAsA('/internal/upstream-token', '{"account":"fake:t:o"}');

  Assert.AreEqual(StatusBadRequest, NotJson.StatusCode);
  Assert.AreEqual(StatusBadRequest, NoSub.StatusCode);
end;

procedure TInternalControllerTests.EveryResponseIsJsonWithNoStore;
begin
  const Key = LinkFakeAccount(UserOne, 'object-1');
  SaveToken(AccessTokenValue, UserOne, ResourceA, TTokenKind.Access);
  const Upstream = Format('{"sub":"user-1","account":"%s"}', [Key]);

  const Responses: TArray<TWebResponse> = [
    FRouter.Dispatch(NewRequest('/internal/introspect', 'token=x', '')),
    CallAsA('/internal/introspect', 'token=' + AccessTokenValue),
    CallAsA('/internal/accounts', '{"sub":"user-1"}'),
    CallAsA('/internal/accounts', 'broken'),
    CallAsA('/internal/upstream-token', Upstream),
    CallAsB('/internal/upstream-token', Upstream)];

  for var Response in Responses do
  begin
    Assert.IsTrue(Response.ContentType.StartsWith('application/json'));
    Assert.AreEqual('no-store', HeaderValue(Response, 'Cache-Control'));
  end;
end;

procedure TInternalControllerTests.UnknownPathIsJson404;
begin
  const Response = FRouter.Dispatch(NewRequest('/internal/nothing', '', BasicHeader('service-a', ServiceSecretA)));

  Assert.AreEqual(StatusNotFound, Response.StatusCode);
  Assert.IsTrue(Response.ContentType.StartsWith('application/json'));
end;

end.
