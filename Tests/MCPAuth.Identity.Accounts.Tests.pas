unit MCPAuth.Identity.Accounts.Tests;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Secret.Interfaces,
  MCPAuth.Identity.Access.Interfaces,
  MCPAuth.Identity.Interfaces,
  MCPAuth.Store.Interfaces,
  MCPAuth.Upstream.Types,
  MCPAuth.Upstream.Interfaces,
  MCPAuth.Identity.Types,
  MCPAuth.Fakes.AccessPolicy,
  MCPAuth.Fakes.Clock,
  MCPAuth.Fakes.UpstreamProvider,
  MCPAuth.Fakes.LoginIdentities;

type
  [TestFixture]
  TLinkedAccountsTests = class
  private
    FClock: TFakeClock;
    FClockReference: IClock;
    FProvider: TFakeUpstreamProvider;
    FProviderReference: IUpstreamProvider;
    FStores: TStoreSet;
    FProtector: ISecretProtector;
    FPolicy: TFakeAccessPolicy;
    FPolicyReference: IAccessPolicy;
    FAccounts: ILinkedAccounts;

    function TokensFor(const ObjectId, RefreshToken: string): TUpstreamTokens;
    function LinkAccount(const ObjectId, RefreshToken: string): TLinkedAccount;
    function KeyOf(const ObjectId: string): TAccountKey;
    function StoredRefreshToken(const UserId, ObjectId: string): string;
    procedure RunInThreads(const Work: TProc<Integer>);
    function WorkFor(const Work: TProc<Integer>; const Index: Integer): TProc;
    procedure SetUpstreamToken(const ExpiresInSeconds: Integer; const RefreshToken: string);
    function SignInAndLink(const SignInObjectId, LinkedObjectId, RefreshToken: string): TAuthUser;

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure ConcurrentFirstSignInsCreateOneUser;

    [Test]
    procedure SignInWithAccountLinkedByOtherUserCreatesNewUser;

    [Test]
    procedure LosingIdentityRaceRemovesTheNewUser;

    [Test]
    procedure SignInWithIdentityYieldsSameUserAndUpdatesLastLogin;

    [Test]
    procedure TwoUsersLinkSameAccountIndependently;

    [Test]
    procedure RelinkReplacesOnlyOwnRefreshToken;

    [Test]
    procedure NeedsReconnectOfOneUserLeavesTheOtherAlone;

    [Test]
    procedure RefreshRequestsTheGrantedScopes;

    [Test]
    procedure RefreshStoresTheScopeOfTheResponse;

    [Test]
    procedure SignInWithoutRefreshTokenKeepsReconnectFlagAndScopes;

    [Test]
    procedure FirstLoginCreatesUserAndAccount;

    [Test]
    procedure SecondLoginWithSameAccountYieldsSameUser;

    [Test]
    procedure LinkAddsAccountToUser;

    [Test]
    procedure LinkingAccountOfOtherUserSucceeds;

    [Test]
    procedure PolicyDenyRaisesAccessDenied;

    [Test]
    procedure StoredRefreshTokenIsEncrypted;

    [Test]
    procedure EmptyRefreshTokenKeepsStoredOne;

    [Test]
    procedure CachedTokenIsReusedUntilMargin;

    [Test]
    procedure ExpiredTokenTriggersRefreshAndStoresNewRefreshToken;

    [Test]
    procedure RefreshWithoutNewRefreshTokenKeepsStoredOne;

    [Test]
    procedure ConcurrentGetAccessTokenRefreshesOnce;

    [Test]
    procedure InvalidGrantMarksNeedsReconnect;

    [Test]
    procedure NeedsReconnectRaisesWithoutUpstreamCall;

    [Test]
    procedure MissingScopesRequireReconnect;

    [Test]
    procedure AlwaysGrantedScopesAreNotChecked;

    [Test]
    procedure AccountOfOtherUserIsNotFound;

    [Test]
    procedure UnknownAccountIsNotFound;

    [Test]
    procedure RewrapsWithCurrentKeyOnRefresh;

    [Test]
    procedure ListForUserReturnsOwnAccountsOnly;

    [Test]
    procedure UnlinkRemovesAccountAndCache;

    [Test]
    procedure UnlinkingTheLastAccountIsAllowed;

    [Test]
    procedure SignInRelinksTheIdentityAccount;
  end;

implementation

uses
  System.DateUtils,
  System.Classes,
  System.SyncObjs,
  Spring.Collections,
  MCPAuth.Secret.KeyRing,
  MCPAuth.Secret.AesGcm,
  MCPAuth.Store.Memory,
  MCPAuth.Identity.Exceptions,
  MCPAuth.Identity.Accounts,
  MCPAuth.Upstream.Providers;

const
  ProviderName = 'fake';
  TenantId = 'tenant-1';
  KeyId = 'k1';
  KeyLength = 32;
  OldKeyId = 'k0';
  AccessTokenScopes = 'openid offline_access Mail.Read';
  ThreadCount = 8;

{ TLinkedAccountsTests }

procedure TLinkedAccountsTests.Setup;
begin
  FClock := TFakeClock.Create(EncodeDateTime(2026, 1, 2, 3, 4, 5, 0));
  FClockReference := FClock;
  FStores := TMemoryStore.CreateSet(FClockReference);
  FProvider := TFakeUpstreamProvider.Create(ProviderName);
  FProviderReference := FProvider;
  FProvider.Scope := AccessTokenScopes;

  var Key: TBytes;
  SetLength(Key, KeyLength);
  FillChar(Key[0], KeyLength, 7);
  const Keys = TCollections.CreateDictionary<string, TBytes>;
  Keys[KeyId] := Key;
  FProtector := TAesGcmProtector.Create(TKeyRing.Create(KeyId, Keys));

  FPolicy := TFakeAccessPolicy.Create;
  FPolicyReference := FPolicy;
  FAccounts := TLinkedAccounts.Create(FStores.Users, FStores.LoginIdentities, FStores.LinkedAccounts, FProtector, FPolicyReference, TUpstreamProviders.Create([FProviderReference]), FClockReference);
end;

procedure TLinkedAccountsTests.TearDown;
begin
  FAccounts := nil;
  FPolicyReference := nil;
  FProtector := nil;
  FStores := Default(TStoreSet);
  FProviderReference := nil;
  FClockReference := nil;
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
  Assert.IsTrue(FStores.LinkedAccounts.TryFind(User.Id, Tokens.Identity.Key, Account), 'account stored');
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
  FStores.LinkedAccounts.TryFind(First.Id, SecondTokens.Identity.Key, Account);
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

procedure TLinkedAccountsTests.LinkingAccountOfOtherUserSucceeds;
begin
  const Owner = FAccounts.ResolveOrCreateUser(TokensFor('object-1', 'refresh-1'));
  const OtherUser = FAccounts.ResolveOrCreateUser(TokensFor('object-2', 'refresh-2'));

  const Linked = FAccounts.Link(OtherUser.Id, TokensFor('object-1', 'refresh-3'));

  Assert.AreEqual(OtherUser.Id, Linked.UserId);
  Assert.AreEqual(2, FAccounts.ListForUser(OtherUser.Id).Count);
  Assert.AreEqual('refresh-1', StoredRefreshToken(Owner.Id, 'object-1'));
  Assert.AreEqual('refresh-3', StoredRefreshToken(OtherUser.Id, 'object-1'));
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
  FStores.LinkedAccounts.TryFind(User.Id, Tokens.Identity.Key, Account);
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
  FStores.LinkedAccounts.TryFind(User.Id, TokensWithoutRefresh.Identity.Key, Account);
  const Context = Format('%s|%s', [User.Id, Account.Key.Value]);
  Assert.AreEqual('refresh-1', FProtector.Unprotect(Account.ProtectedRefreshToken, Context));
end;

function TLinkedAccountsTests.KeyOf(const ObjectId: string): TAccountKey;
begin
  Result := TokensFor(ObjectId, '').Identity.Key;
end;

function TLinkedAccountsTests.LinkAccount(const ObjectId, RefreshToken: string): TLinkedAccount;
begin
  var Tokens := TokensFor(ObjectId, RefreshToken);
  Tokens.Scope := AccessTokenScopes;

  const User = FAccounts.ResolveOrCreateUser(Tokens);
  FStores.LinkedAccounts.TryFind(User.Id, Tokens.Identity.Key, Result);
  Assert.AreEqual(User.Id, Result.UserId);
end;

function TLinkedAccountsTests.StoredRefreshToken(const UserId, ObjectId: string): string;
begin
  var Account: TLinkedAccount;
  Assert.IsTrue(FStores.LinkedAccounts.TryFind(UserId, KeyOf(ObjectId), Account), 'account stored');

  Result := FProtector.Unprotect(Account.ProtectedRefreshToken, Format('%s|%s', [Account.UserId, Account.Key.Value]));
end;

procedure TLinkedAccountsTests.SetUpstreamToken(const ExpiresInSeconds: Integer; const RefreshToken: string);
begin
  FProvider.ExpiresAtUtc := IncSecond(FClock.NowUtc, ExpiresInSeconds);
  FProvider.RefreshToken := RefreshToken;
end;

procedure TLinkedAccountsTests.RunInThreads(const Work: TProc<Integer>);
begin
  var Threads: TArray<TThread>;
  for var Index := 0 to ThreadCount - 1 do
  begin
    Threads := Threads + [TThread.CreateAnonymousThread(WorkFor(Work, Index))];
    Threads[Index].FreeOnTerminate := False;
  end;

  for var Thread in Threads do
  begin
    Thread.Start;
  end;
  for var Thread in Threads do
  begin
    Thread.WaitFor;
    Thread.Free;
  end;
end;

function TLinkedAccountsTests.WorkFor(const Work: TProc<Integer>; const Index: Integer): TProc;
begin
  Result :=
    procedure
    begin
      Work(Index);
    end;
end;

procedure TLinkedAccountsTests.ConcurrentFirstSignInsCreateOneUser;
begin
  var UserIds: TArray<string>;
  SetLength(UserIds, ThreadCount);
  var FailureCount := 0;

  RunInThreads(
    procedure(Index: Integer)
    begin
      try
        UserIds[Index] := FAccounts.ResolveOrCreateUser(TokensFor('object-1', 'refresh-1')).Id;
      except
        TInterlocked.Increment(FailureCount);
      end;
    end);

  Assert.AreEqual(0, FailureCount, 'failures');
  for var UserId in UserIds do
  begin
    Assert.AreEqual(UserIds[0], UserId);
  end;
end;

function TLinkedAccountsTests.SignInAndLink(const SignInObjectId, LinkedObjectId, RefreshToken: string): TAuthUser;
begin
  Result := FAccounts.ResolveOrCreateUser(TokensFor(SignInObjectId, 'refresh-' + SignInObjectId));
  var Tokens := TokensFor(LinkedObjectId, RefreshToken);
  Tokens.Scope := AccessTokenScopes;
  FAccounts.Link(Result.Id, Tokens);
end;

procedure TLinkedAccountsTests.SignInWithAccountLinkedByOtherUserCreatesNewUser;
begin
  const Owner = SignInAndLink('object-1', 'object-2', 'refresh-2');

  const SignedIn = FAccounts.ResolveOrCreateUser(TokensFor('object-2', 'refresh-x'));

  Assert.AreNotEqual(Owner.Id, SignedIn.Id);
  Assert.AreEqual(2, FAccounts.ListForUser(Owner.Id).Count);
  Assert.AreEqual('refresh-2', StoredRefreshToken(Owner.Id, 'object-2'));
end;

procedure TLinkedAccountsTests.LosingIdentityRaceRemovesTheNewUser;
begin
  var Winner := Default(TAuthUser);
  Winner.Id           := 'winner-user';
  Winner.DisplayName  := 'Winner';
  Winner.CreatedAtUtc := FClock.NowUtc;
  FStores.Users.Save(Winner);
  const Racing = TRacingLoginIdentityRepository.Create(FStores.LoginIdentities);
  const RacingReference: ILoginIdentityRepository = Racing;
  Racing.WinnerUserId := Winner.Id;
  const Accounts: ILinkedAccounts = TLinkedAccounts.Create(FStores.Users, RacingReference, FStores.LinkedAccounts, FProtector, FPolicyReference, TUpstreamProviders.Create([FProviderReference]), FClockReference);

  const User = Accounts.ResolveOrCreateUser(TokensFor('object-1', 'refresh-1'));

  Assert.AreEqual(Winner.Id, User.Id);
  var Orphan: TAuthUser;
  Assert.IsFalse(Racing.LosingUserId.IsEmpty, 'the race happened');
  Assert.IsFalse(FStores.Users.TryGet(Racing.LosingUserId, Orphan), 'the losing user is removed');
end;

procedure TLinkedAccountsTests.SignInWithIdentityYieldsSameUserAndUpdatesLastLogin;
begin
  const First = FAccounts.ResolveOrCreateUser(TokensFor('object-1', 'refresh-1'));
  FClock.AdvanceSeconds(SecsPerHour);

  const Second = FAccounts.ResolveOrCreateUser(TokensFor('object-1', 'refresh-2'));

  Assert.AreEqual(First.Id, Second.Id);
  var Identity: TLoginIdentity;
  Assert.IsTrue(FStores.LoginIdentities.TryFind(KeyOf('object-1'), Identity), 'identity stored');
  Assert.AreEqual(First.Id, Identity.UserId);
  Assert.AreEqual(FClock.NowUtc, Identity.LastLoginAtUtc);
end;

procedure TLinkedAccountsTests.TwoUsersLinkSameAccountIndependently;
begin
  const UserA = SignInAndLink('object-a', 'object-shared', 'rt-a');
  const UserB = SignInAndLink('object-b', 'object-shared', 'rt-b');
  SetUpstreamToken(3600, '');

  FAccounts.Unlink(UserA.Id, KeyOf('object-shared'));
  FAccounts.GetAccessToken(UserB.Id, KeyOf('object-shared'), ['Mail.Read']);

  Assert.AreEqual(1, FAccounts.ListForUser(UserA.Id).Count);
  Assert.AreEqual(2, FAccounts.ListForUser(UserB.Id).Count);
  Assert.AreEqual('rt-b', FProvider.LastRefreshInput);
end;

procedure TLinkedAccountsTests.RelinkReplacesOnlyOwnRefreshToken;
begin
  const UserA = SignInAndLink('object-a', 'object-shared', 'rt-a');
  const UserB = SignInAndLink('object-b', 'object-shared', 'rt-b');

  FAccounts.Link(UserA.Id, TokensFor('object-shared', 'rt-a2'));

  Assert.AreEqual('rt-a2', StoredRefreshToken(UserA.Id, 'object-shared'));
  Assert.AreEqual('rt-b', StoredRefreshToken(UserB.Id, 'object-shared'));
end;

procedure TLinkedAccountsTests.NeedsReconnectOfOneUserLeavesTheOtherAlone;
begin
  const UserA = SignInAndLink('object-a', 'object-shared', 'rt-a');
  const UserB = SignInAndLink('object-b', 'object-shared', 'rt-b');
  FProvider.IsRevoked := True;

  Assert.WillRaise(
    procedure
    begin
      FAccounts.GetAccessToken(UserA.Id, KeyOf('object-shared'), ['Mail.Read']);
    end,
    ELinkedAccountNeedsReconnect);

  var Stored: TLinkedAccount;
  FStores.LinkedAccounts.TryFind(UserA.Id, KeyOf('object-shared'), Stored);
  Assert.IsTrue(Stored.NeedsReconnect, 'A needs reconnect');
  FStores.LinkedAccounts.TryFind(UserB.Id, KeyOf('object-shared'), Stored);
  Assert.IsFalse(Stored.NeedsReconnect, 'B untouched');
end;

procedure TLinkedAccountsTests.RefreshRequestsTheGrantedScopes;
begin
  const Account = LinkAccount('object-1', 'refresh-1');
  SetUpstreamToken(3600, 'refresh-2');

  FAccounts.GetAccessToken(Account.UserId, Account.Key, ['Mail.Read']);

  Assert.AreEqual(AccessTokenScopes, string.Join(' ', FProvider.LastRefreshScopes));
end;

procedure TLinkedAccountsTests.RefreshStoresTheScopeOfTheResponse;
begin
  const Account = LinkAccount('object-1', 'refresh-1');
  SetUpstreamToken(3600, 'refresh-2');
  FProvider.Scope := 'openid offline_access';

  FAccounts.GetAccessToken(Account.UserId, Account.Key, ['Mail.Read']);

  var Stored: TLinkedAccount;
  FStores.LinkedAccounts.TryFind(Account.UserId, Account.Key, Stored);
  Assert.AreEqual('openid offline_access', Stored.GrantedScopes, 'an administrator removed Mail.Read');
end;

procedure TLinkedAccountsTests.SignInWithoutRefreshTokenKeepsReconnectFlagAndScopes;
begin
  const Account = LinkAccount('object-1', 'refresh-1');
  var Stored: TLinkedAccount;
  FStores.LinkedAccounts.TryFind(Account.UserId, Account.Key, Stored);
  Stored.NeedsReconnect := True;
  FStores.LinkedAccounts.Save(Stored);

  FAccounts.ResolveOrCreateUser(TokensFor('object-1', ''));

  FStores.LinkedAccounts.TryFind(Account.UserId, Account.Key, Stored);
  Assert.IsTrue(Stored.NeedsReconnect, 'the stored refresh token is still the revoked one');
  Assert.AreEqual(AccessTokenScopes, Stored.GrantedScopes, 'the scopes still describe the stored refresh token');
end;

procedure TLinkedAccountsTests.CachedTokenIsReusedUntilMargin;
begin
  const Account = LinkAccount('object-1', 'refresh-1');
  SetUpstreamToken(3600, 'refresh-2');

  const First = FAccounts.GetAccessToken(Account.UserId, Account.Key, ['Mail.Read']);
  FClock.AdvanceSeconds(3000);
  const Second = FAccounts.GetAccessToken(Account.UserId, Account.Key, ['Mail.Read']);

  Assert.AreEqual(1, FProvider.RefreshCount, 'still cached');
  Assert.AreEqual(First.AccessToken, Second.AccessToken);

  // 3600 s minus the 60 s margin: 3540 s after the refresh
  FClock.AdvanceSeconds(540);
  FAccounts.GetAccessToken(Account.UserId, Account.Key, ['Mail.Read']);

  Assert.AreEqual(2, FProvider.RefreshCount, 'refreshed at the margin');
end;

procedure TLinkedAccountsTests.ExpiredTokenTriggersRefreshAndStoresNewRefreshToken;
begin
  const Account = LinkAccount('object-1', 'refresh-1');
  SetUpstreamToken(3600, 'refresh-2');

  const Token = FAccounts.GetAccessToken(Account.UserId, Account.Key, ['Mail.Read']);

  Assert.AreEqual('refresh-1', FProvider.LastRefreshInput);
  Assert.AreEqual('refresh-2', StoredRefreshToken(Account.UserId, 'object-1'));
  Assert.AreEqual(FProvider.ExpiresAtUtc, Token.ExpiresAtUtc, 0.00001);
  Assert.IsNotEmpty(Token.AccessToken);
end;

procedure TLinkedAccountsTests.RefreshWithoutNewRefreshTokenKeepsStoredOne;
begin
  const Account = LinkAccount('object-1', 'refresh-1');
  SetUpstreamToken(3600, '');

  FAccounts.GetAccessToken(Account.UserId, Account.Key, ['Mail.Read']);

  Assert.AreEqual('refresh-1', StoredRefreshToken(Account.UserId, 'object-1'));
end;

procedure TLinkedAccountsTests.ConcurrentGetAccessTokenRefreshesOnce;
begin
  const Account = LinkAccount('object-1', 'refresh-1');
  SetUpstreamToken(3600, 'refresh-2');
  FProvider.RefreshDelayMs := 200;

  var FailureCount := 0;
  var Threads: TArray<TThread>;
  for var Index := 1 to ThreadCount do
  begin
    const Thread = TThread.CreateAnonymousThread(
      procedure
      begin
        try
          FAccounts.GetAccessToken(Account.UserId, Account.Key, ['Mail.Read']);
        except
          TInterlocked.Increment(FailureCount);
        end;
      end);
    Thread.FreeOnTerminate := False;
    Threads := Threads + [Thread];
  end;

  for var Thread in Threads do
  begin
    Thread.Start;
  end;
  for var Thread in Threads do
  begin
    Thread.WaitFor;
    Thread.Free;
  end;

  Assert.AreEqual(0, FailureCount, 'failures');
  Assert.AreEqual(1, FProvider.RefreshCount, 'refresh calls');
  Assert.AreEqual('refresh-2', StoredRefreshToken(Account.UserId, 'object-1'));
end;

procedure TLinkedAccountsTests.InvalidGrantMarksNeedsReconnect;
begin
  const Account = LinkAccount('object-1', 'refresh-1');
  FProvider.IsRevoked := True;

  try
    FAccounts.GetAccessToken(Account.UserId, Account.Key, ['Mail.Read']);
    Assert.Fail('ELinkedAccountNeedsReconnect expected');
  except
    on Error: ELinkedAccountNeedsReconnect do
    begin
      Assert.AreEqual('revoked', Error.Reason);
    end;
  end;

  var Stored: TLinkedAccount;
  FStores.LinkedAccounts.TryFind(Account.UserId, Account.Key, Stored);
  Assert.IsTrue(Stored.NeedsReconnect, 'NeedsReconnect stored');
end;

procedure TLinkedAccountsTests.NeedsReconnectRaisesWithoutUpstreamCall;
begin
  const Account = LinkAccount('object-1', 'refresh-1');
  var Stored: TLinkedAccount;
  FStores.LinkedAccounts.TryFind(Account.UserId, Account.Key, Stored);
  Stored.NeedsReconnect := True;
  FStores.LinkedAccounts.Save(Stored);
  SetUpstreamToken(3600, 'refresh-2');

  try
    FAccounts.GetAccessToken(Account.UserId, Account.Key, ['Mail.Read']);
    Assert.Fail('ELinkedAccountNeedsReconnect expected');
  except
    on Error: ELinkedAccountNeedsReconnect do
    begin
      Assert.AreEqual('revoked', Error.Reason);
    end;
  end;

  Assert.AreEqual(0, FProvider.RefreshCount, 'upstream calls');
end;

procedure TLinkedAccountsTests.MissingScopesRequireReconnect;
begin
  const Account = LinkAccount('object-1', 'refresh-1');
  SetUpstreamToken(3600, 'refresh-2');

  try
    FAccounts.GetAccessToken(Account.UserId, Account.Key, ['mail.read', 'Calendars.Read']);
    Assert.Fail('ELinkedAccountNeedsReconnect expected');
  except
    on Error: ELinkedAccountNeedsReconnect do
    begin
      Assert.AreEqual('missing_scopes', Error.Reason);
    end;
  end;

  Assert.AreEqual(0, FProvider.RefreshCount, 'upstream calls');
end;

procedure TLinkedAccountsTests.AlwaysGrantedScopesAreNotChecked;
begin
  const Account = LinkAccount('object-1', 'refresh-1');
  SetUpstreamToken(3600, 'refresh-2');

  const Token = FAccounts.GetAccessToken(Account.UserId, Account.Key, ['mail.read', 'openid', 'profile', 'email', 'offline_access']);

  Assert.IsNotEmpty(Token.AccessToken);
end;

procedure TLinkedAccountsTests.AccountOfOtherUserIsNotFound;
begin
  const Account = LinkAccount('object-1', 'refresh-1');
  const OtherUser = FAccounts.ResolveOrCreateUser(TokensFor('object-2', 'refresh-2'));

  Assert.WillRaise(
    procedure
    begin
      FAccounts.GetAccessToken(OtherUser.Id, Account.Key, ['Mail.Read']);
    end,
    ELinkedAccountNotFound);
end;

procedure TLinkedAccountsTests.UnknownAccountIsNotFound;
begin
  const Account = LinkAccount('object-1', 'refresh-1');

  Assert.WillRaise(
    procedure
    begin
      FAccounts.GetAccessToken(Account.UserId, KeyOf('unknown'), []);
    end,
    ELinkedAccountNotFound);
end;

procedure TLinkedAccountsTests.RewrapsWithCurrentKeyOnRefresh;
begin
  var OldKey: TBytes;
  SetLength(OldKey, KeyLength);
  FillChar(OldKey[0], KeyLength, 9);
  var NewKey: TBytes;
  SetLength(NewKey, KeyLength);
  FillChar(NewKey[0], KeyLength, 7);

  const OldKeys = TCollections.CreateDictionary<string, TBytes>;
  OldKeys[OldKeyId] := OldKey;
  const OldProtector: ISecretProtector = TAesGcmProtector.Create(TKeyRing.Create(OldKeyId, OldKeys));

  const Account = LinkAccount('object-1', 'refresh-1');
  var Stored: TLinkedAccount;
  FStores.LinkedAccounts.TryFind(Account.UserId, Account.Key, Stored);
  const Context = Format('%s|%s', [Account.UserId, Account.Key.Value]);
  Stored.ProtectedRefreshToken := OldProtector.Protect('refresh-1', Context);
  FStores.LinkedAccounts.Save(Stored);

  const RotatedKeys = TCollections.CreateDictionary<string, TBytes>;
  RotatedKeys[OldKeyId] := OldKey;
  RotatedKeys[KeyId] := NewKey;
  const RotatedProtector: ISecretProtector = TAesGcmProtector.Create(TKeyRing.Create(KeyId, RotatedKeys));
  const Accounts: ILinkedAccounts = TLinkedAccounts.Create(FStores.Users, FStores.LoginIdentities, FStores.LinkedAccounts, RotatedProtector, FPolicyReference, TUpstreamProviders.Create([FProviderReference]), FClockReference);
  Assert.IsTrue(RotatedProtector.NeedsRewrap(Stored.ProtectedRefreshToken), 'precondition: old key');
  SetUpstreamToken(3600, '');

  Accounts.GetAccessToken(Account.UserId, Account.Key, ['Mail.Read']);

  FStores.LinkedAccounts.TryFind(Account.UserId, Account.Key, Stored);
  Assert.IsFalse(RotatedProtector.NeedsRewrap(Stored.ProtectedRefreshToken), 'rewrapped');
  Assert.AreEqual('refresh-1', RotatedProtector.Unprotect(Stored.ProtectedRefreshToken, Context));
end;

procedure TLinkedAccountsTests.ListForUserReturnsOwnAccountsOnly;
begin
  const Account = LinkAccount('object-1', 'refresh-1');
  FAccounts.Link(Account.UserId, TokensFor('object-2', 'refresh-2'));
  FAccounts.ResolveOrCreateUser(TokensFor('object-3', 'refresh-3'));

  Assert.AreEqual(2, FAccounts.ListForUser(Account.UserId).Count);
end;

procedure TLinkedAccountsTests.UnlinkRemovesAccountAndCache;
begin
  const Account = LinkAccount('object-1', 'refresh-1');
  FAccounts.Link(Account.UserId, TokensFor('object-2', 'refresh-2'));
  SetUpstreamToken(3600, 'refresh-3');
  FAccounts.GetAccessToken(Account.UserId, Account.Key, []);
  const RefreshesBefore = FProvider.RefreshCount;

  FAccounts.Unlink(Account.UserId, Account.Key);
  FAccounts.Link(Account.UserId, TokensFor('object-1', 'refresh-4'));
  FAccounts.GetAccessToken(Account.UserId, Account.Key, []);

  Assert.AreEqual(RefreshesBefore + 1, FProvider.RefreshCount, 'cache entry removed');
  Assert.AreEqual(2, FAccounts.ListForUser(Account.UserId).Count);
end;

procedure TLinkedAccountsTests.UnlinkingTheLastAccountIsAllowed;
begin
  const Account = LinkAccount('object-1', 'refresh-1');

  FAccounts.Unlink(Account.UserId, Account.Key);

  Assert.AreEqual(0, FAccounts.ListForUser(Account.UserId).Count);
end;

procedure TLinkedAccountsTests.SignInRelinksTheIdentityAccount;
begin
  const Account = LinkAccount('object-1', 'refresh-1');
  FAccounts.Unlink(Account.UserId, Account.Key);

  const User = FAccounts.ResolveOrCreateUser(TokensFor('object-1', 'refresh-2'));

  Assert.AreEqual(Account.UserId, User.Id);
  Assert.AreEqual(1, FAccounts.ListForUser(User.Id).Count);
  Assert.AreEqual('refresh-2', StoredRefreshToken(User.Id, 'object-1'));
end;

end.
