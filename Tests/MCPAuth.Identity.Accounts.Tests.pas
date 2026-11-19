unit MCPAuth.Identity.Accounts.Tests;

interface

uses
  DUnitX.TestFramework,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Secret.Interfaces,
  MCPAuth.Identity.Access.Interfaces,
  MCPAuth.Identity.Interfaces,
  MCPAuth.Store.Interfaces,
  MCPAuth.Upstream.Types,
  MCPAuth.Fakes.AccessPolicy;

type
  [TestFixture]
  TLinkedAccountsTests = class
  private
    FClock: IClock;
    FStores: TStoreSet;
    FProtector: ISecretProtector;
    FPolicy: TFakeAccessPolicy;
    FPolicyReference: IAccessPolicy;
    FAccounts: ILinkedAccounts;

    function TokensFor(const ObjectId, RefreshToken: string): TUpstreamTokens;

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure FirstLoginCreatesUserAndAccount;

    [Test]
    procedure SecondLoginWithSameAccountYieldsSameUser;

    [Test]
    procedure LinkAddsAccountToUser;

    [Test]
    procedure LinkingAccountOfOtherUserRaises;

    [Test]
    procedure PolicyDenyRaisesAccessDenied;

    [Test]
    procedure StoredRefreshTokenIsEncrypted;

    [Test]
    procedure EmptyRefreshTokenKeepsStoredOne;
  end;

implementation

uses
  System.SysUtils,
  System.DateUtils,
  Spring.Collections,
  MCPAuth.Fakes.Clock,
  MCPAuth.Secret.KeyRing,
  MCPAuth.Secret.AesGcm,
  MCPAuth.Store.Memory,
  MCPAuth.Identity.Types,
  MCPAuth.Identity.Exceptions,
  MCPAuth.Identity.Accounts;

const
  ProviderName = 'fake';
  TenantId = 'tenant-1';
  KeyId = 'k1';
  KeyLength = 32;

{ TLinkedAccountsTests }

procedure TLinkedAccountsTests.Setup;
begin
  FClock := TFakeClock.Create(EncodeDateTime(2026, 1, 2, 3, 4, 5, 0));
  FStores := TMemoryStore.CreateSet(FClock);

  var Key: TBytes;
  SetLength(Key, KeyLength);
  FillChar(Key[0], KeyLength, 7);
  const Keys = TCollections.CreateDictionary<string, TBytes>;
  Keys[KeyId] := Key;
  FProtector := TAesGcmProtector.Create(TKeyRing.Create(KeyId, Keys));

  FPolicy := TFakeAccessPolicy.Create;
  FPolicyReference := FPolicy;
  FAccounts := TLinkedAccounts.Create(FStores.Users, FStores.LinkedAccounts, FProtector, FPolicyReference, FClock);
end;

procedure TLinkedAccountsTests.TearDown;
begin
  FAccounts := nil;
  FPolicyReference := nil;
  FProtector := nil;
  FStores := Default(TStoreSet);
  FClock := nil;
end;

function TLinkedAccountsTests.TokensFor(const ObjectId, RefreshToken: string): TUpstreamTokens;
begin
  Result := Default(TUpstreamTokens);
  Result.AccessToken := 'upstream-access';
  Result.RefreshToken := RefreshToken;
  Result.Scope := 'openid offline_access';
  Result.Identity.Key.Provider := ProviderName;
  Result.Identity.Key.TenantId := TenantId;
  Result.Identity.Key.ObjectId := ObjectId;
  Result.Identity.DisplayName := 'Test User';
  Result.Identity.UserName := 'user@example.test';
end;

procedure TLinkedAccountsTests.FirstLoginCreatesUserAndAccount;
begin
  const Tokens = TokensFor('object-1', 'refresh-1');

  const User = FAccounts.ResolveOrCreateUser(Tokens);

  var Stored: TAuthUser;
  Assert.IsTrue(FStores.Users.TryGet(User.Id, Stored), 'user stored');
  Assert.AreEqual('Test User', Stored.DisplayName);

  var Account: TLinkedAccount;
  Assert.IsTrue(FStores.LinkedAccounts.TryFind(Tokens.Identity.Key, Account), 'account stored');
  Assert.AreEqual(User.Id, Account.UserId);
  Assert.AreEqual('openid offline_access', Account.GrantedScopes);
  Assert.AreEqual('user@example.test', Account.UserName);
end;

procedure TLinkedAccountsTests.SecondLoginWithSameAccountYieldsSameUser;
begin
  const First = FAccounts.ResolveOrCreateUser(TokensFor('object-1', 'refresh-1'));
  var SecondTokens := TokensFor('object-1', 'refresh-2');
  SecondTokens.Scope := 'openid offline_access mail.read';

  const Second = FAccounts.ResolveOrCreateUser(SecondTokens);

  Assert.AreEqual(First.Id, Second.Id);

  var Account: TLinkedAccount;
  FStores.LinkedAccounts.TryFind(SecondTokens.Identity.Key, Account);
  const Context = Format('%s|%s', [First.Id, Account.Key.Value]);
  Assert.AreEqual('refresh-2', FProtector.Unprotect(Account.ProtectedRefreshToken, Context));
  Assert.AreEqual('openid offline_access mail.read', Account.GrantedScopes);
end;

procedure TLinkedAccountsTests.LinkAddsAccountToUser;
begin
  const User = FAccounts.ResolveOrCreateUser(TokensFor('object-1', 'refresh-1'));

  const Linked = FAccounts.Link(User.Id, TokensFor('object-2', 'refresh-2'));

  Assert.AreEqual(User.Id, Linked.UserId);
  Assert.AreEqual(2, FStores.LinkedAccounts.ListForUser(User.Id).Count);
end;

procedure TLinkedAccountsTests.LinkingAccountOfOtherUserRaises;
begin
  FAccounts.ResolveOrCreateUser(TokensFor('object-1', 'refresh-1'));
  const OtherUser = FAccounts.ResolveOrCreateUser(TokensFor('object-2', 'refresh-2'));

  Assert.WillRaise(
    procedure
    begin
      FAccounts.Link(OtherUser.Id, TokensFor('object-1', 'refresh-3'));
    end,
    EAccountLinkedToOtherUser);
end;

procedure TLinkedAccountsTests.PolicyDenyRaisesAccessDenied;
begin
  const User = FAccounts.ResolveOrCreateUser(TokensFor('object-1', 'refresh-1'));
  FPolicy.IsAllowing := False;

  Assert.WillRaise(
    procedure
    begin
      FAccounts.ResolveOrCreateUser(TokensFor('object-2', 'refresh-2'));
    end,
    EAccessDenied);
  Assert.WillRaise(
    procedure
    begin
      FAccounts.Link(User.Id, TokensFor('object-3', 'refresh-3'));
    end,
    EAccessDenied);
end;

procedure TLinkedAccountsTests.StoredRefreshTokenIsEncrypted;
begin
  const RefreshToken = 'very-secret-upstream-refresh-token';
  const Tokens = TokensFor('object-1', RefreshToken);

  const User = FAccounts.ResolveOrCreateUser(Tokens);

  var Account: TLinkedAccount;
  FStores.LinkedAccounts.TryFind(Tokens.Identity.Key, Account);
  const StoredText = TEncoding.ANSI.GetString(Account.ProtectedRefreshToken);
  Assert.IsFalse(StoredText.Contains(RefreshToken), 'plain refresh token stored');

  const Context = Format('%s|%s', [User.Id, Account.Key.Value]);
  Assert.AreEqual(RefreshToken, FProtector.Unprotect(Account.ProtectedRefreshToken, Context));
end;

procedure TLinkedAccountsTests.EmptyRefreshTokenKeepsStoredOne;
begin
  const User = FAccounts.ResolveOrCreateUser(TokensFor('object-1', 'refresh-1'));

  const TokensWithoutRefresh = TokensFor('object-1', '');
  FAccounts.ResolveOrCreateUser(TokensWithoutRefresh);

  var Account: TLinkedAccount;
  FStores.LinkedAccounts.TryFind(TokensWithoutRefresh.Identity.Key, Account);
  const Context = Format('%s|%s', [User.Id, Account.Key.Value]);
  Assert.AreEqual('refresh-1', FProtector.Unprotect(Account.ProtectedRefreshToken, Context));
end;

end.
