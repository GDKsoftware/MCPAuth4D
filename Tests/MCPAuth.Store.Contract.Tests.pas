unit MCPAuth.Store.Contract.Tests;

interface

uses
  System.SysUtils,
  System.Classes,
  DUnitX.TestFramework,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Fakes.Clock,
  MCPAuth.Identity.Types,
  MCPAuth.OAuth.Types,
  MCPAuth.Store.Interfaces;

type
  // Shared behaviour every store implementation must show. A concrete fixture derives from it,
  // carries [TestFixture] and supplies the store under test.
  TStoreContractTests = class
  private
    FFakeClock: TFakeClock;
    FClock: IClock;
    FStores: TStoreSet;
    FConsumeSuccesses: Integer;
    FFailures: Integer;

    function BaseTime: TDateTime;
    function NewAccount(const UserId, ObjectId: string): TLinkedAccount;
    function NewIdentity(const UserId, TenantId, ObjectId: string): TLoginIdentity;
    procedure SaveUser(const UserId: string);
    function NewPending(const Id: string; const ExpiresAtUtc: TDateTime): TPendingAuthorization;
    function NewGrant(const CodeHash: string; const ExpiresAtUtc: TDateTime): TAuthorizationGrant;
    function NewToken(const Hash, FamilyId, UserId: string; const ExpiresAtUtc: TDateTime): TIssuedToken;
    function NewTokenFor(const Hash, FamilyId, UserId, Resource: string): TIssuedToken;

    procedure RunWorker(const Worker: Integer);
    function CreateWorker(const Worker: Integer): TThread;
    function CountMissingKeys: Integer;
    procedure RunLinkWorker(const Worker: Integer);
    function CreateLinkWorker(const Worker: Integer): TThread;

  protected
    // Passes the running test when UnavailableReason is not empty.
    procedure RequireStore;

    function CreateStore(const Clock: IClock): TStoreSet; virtual; abstract;

    // A non-empty reason makes every test pass without touching a store, for stores that need an external server.
    function UnavailableReason: string; virtual;

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure SavedUserCanBeRead;

    [Test]
    procedure UnknownUserIsNotFound;

    [Test]
    procedure DeletedUserIsNotFound;

    [Test]
    procedure LinkedAccountRoundTrips;

    [Test]
    procedure SameAccountForTwoUsersAreSeparateRows;

    [Test]
    procedure DeleteOfOneUserKeepsTheOtherRow;

    [Test]
    procedure TryFindOfOtherUserIsFalse;

    [Test]
    procedure ConcurrentSavesOfSameAccountForTwoUsersKeepBothRows;

    [Test]
    procedure ListForUserReturnsOnlyOwnAccounts;

    [Test]
    procedure DeleteRemovesOnlyThatAccount;

    [Test]
    procedure PendingCanBeReadThenTakenOnce;

    [Test]
    procedure ExpiredPendingIsNotTaken;

    [Test]
    procedure GrantIsTakenOnce;

    [Test]
    procedure ExpiredGrantIsNotTaken;

    [Test]
    procedure DeleteExpiredRemovesOnlyExpiredPending;

    [Test]
    procedure DeleteExpiredRemovesOnlyExpiredGrants;

    [Test]
    procedure RefreshTokenIsConsumedOnce;

    [Test]
    procedure ConsumedTokenIsKnownWithFamily;

    [Test]
    procedure DeleteFamilyRemovesAllTokensOfFamily;

    [Test]
    procedure DeleteForUserRemovesAllTokensOfUser;

    [Test]
    procedure ListFamiliesForUserGroupsByFamily;

    [Test]
    procedure HasActiveFamilyIsFalseAfterDeleteFamily;

    [Test]
    procedure TokensSavedAfterDeleteFamilyStayRevoked;

    [Test]
    procedure DeleteExpiredForgetsOldRevocationsWithoutTokens;

    [Test]
    procedure DeleteExpiredRemovesOnlyExpired;

    [Test]
    procedure ExpiredSessionIsNotFound;

    [Test]
    procedure ClientRoundTrips;

    [Test]
    procedure RemovedSessionIsNotFound;

    [Test]
    procedure ConcurrentSavesAreSafe;

    [Test]
    procedure UserWithNonAsciiNameRoundTrips;

    [Test]
    procedure LinkedAccountWithNonAsciiNamesRoundTrips;

    [Test]
    procedure ClientWithNonAsciiNameRoundTrips;

    [Test]
    procedure LoginIdentityRoundTrips;

    [Test]
    procedure IdentityIsFoundRegardlessOfKeyCase;

    [Test]
    procedure SavingIdentityOfOtherUserRaises;

    [Test]
    procedure SavingOwnIdentityAgainUpdatesIt;

    [Test]
    procedure ListIdentitiesForUserReturnsOnlyOwn;
  end;

implementation

uses
  System.SyncObjs,
  System.DateUtils,
  MCPAuth.Identity.Exceptions,
  MCPAuth.Web.Types;

const
  ThreadCount = 8;
  SavesPerThread = 200;
  LinkSavesPerThread = 20;
  SharedTokenHash = 'shared-token';
  // 'Jos' + e acute + ' M' + u umlaut + 'ller-' + O stroke + 'deg' + a ring + 'rd'
  LatinName = 'Jos'#$00E9' M'#$00FC'ller-'#$00D8'deg'#$00E5'rd';
  // C acute + 'wiczenie ' + sharp s + ' ' + euro sign
  MixedName = #$0106'wiczenie '#$00DF' '#$20AC;

{ TStoreContractTests }

procedure TStoreContractTests.Setup;
begin
  FFakeClock := TFakeClock.Create(BaseTime);
  FClock := FFakeClock;

  const IsStoreAvailable = UnavailableReason.IsEmpty;
  if IsStoreAvailable then
  begin
    FStores := CreateStore(FClock);
  end;
end;

procedure TStoreContractTests.TearDown;
begin
  FStores := Default(TStoreSet);
  FClock := nil;
  FFakeClock := nil;
end;

function TStoreContractTests.UnavailableReason: string;
begin
  Result := '';
end;

procedure TStoreContractTests.RequireStore;
begin
  const Reason = UnavailableReason;
  if not Reason.IsEmpty then
  begin
    Assert.Pass(Reason);
  end;
end;

function TStoreContractTests.BaseTime: TDateTime;
begin
  Result := EncodeDateTime(2026, 6, 1, 12, 0, 0, 0);
end;

function TStoreContractTests.NewAccount(const UserId, ObjectId: string): TLinkedAccount;
begin
  Result := Default(TLinkedAccount);
  Result.Key.Provider := 'microsoft';
  Result.Key.TenantId := 'tenant-1';
  Result.Key.ObjectId := ObjectId;
  Result.UserId := UserId;
  Result.DisplayName := 'Display ' + ObjectId;
  Result.UserName := ObjectId + '@example.test';
  Result.GrantedScopes := 'scope.a scope.b';
  Result.ProtectedRefreshToken := TBytes.Create(0, 1, 2, 254, 255);
  Result.NeedsReconnect := True;
  Result.LinkedAtUtc := BaseTime;
  Result.UpdatedAtUtc := IncHour(BaseTime, 1);
end;

function TStoreContractTests.NewIdentity(const UserId, TenantId, ObjectId: string): TLoginIdentity;
begin
  Result := Default(TLoginIdentity);
  Result.Key.Provider    := 'microsoft';
  Result.Key.TenantId    := TenantId;
  Result.Key.ObjectId    := ObjectId;
  Result.UserId          := UserId;
  Result.UserName        := ObjectId + '@example.test';
  Result.CreatedAtUtc    := BaseTime;
  Result.LastLoginAtUtc  := IncHour(BaseTime, 1);
end;

procedure TStoreContractTests.SaveUser(const UserId: string);
begin
  var User := Default(TAuthUser);
  User.Id           := UserId;
  User.DisplayName  := 'User ' + UserId;
  User.CreatedAtUtc := BaseTime;
  FStores.Users.Save(User);
end;

function TStoreContractTests.NewPending(const Id: string; const ExpiresAtUtc: TDateTime): TPendingAuthorization;
begin
  Result := Default(TPendingAuthorization);
  Result.Id := Id;
  Result.Purpose := TLoginPurpose.LinkAccount;
  Result.ClientId := 'client-1';
  Result.RedirectUri := 'https://client.example.test/callback';
  Result.CodeChallenge := 'challenge';
  Result.State := 'state';
  Result.Scope := 'scope';
  Result.Resource := 'https://resource.example.test';
  Result.UserId := 'user-1';
  Result.UpstreamProvider := 'microsoft';
  Result.UpstreamVerifier := 'verifier';
  Result.BrowserBindingHash := 'binding-hash';
  Result.ExpiresAtUtc := ExpiresAtUtc;
end;

function TStoreContractTests.NewGrant(const CodeHash: string; const ExpiresAtUtc: TDateTime): TAuthorizationGrant;
begin
  Result := Default(TAuthorizationGrant);
  Result.CodeHash := CodeHash;
  Result.ClientId := 'client-1';
  Result.RedirectUri := 'https://client.example.test/callback';
  Result.CodeChallenge := 'challenge';
  Result.UserId := 'user-1';
  Result.Scope := 'scope';
  Result.Resource := 'https://resource.example.test';
  Result.ExpiresAtUtc := ExpiresAtUtc;
end;

function TStoreContractTests.NewToken(const Hash, FamilyId, UserId: string; const ExpiresAtUtc: TDateTime): TIssuedToken;
begin
  Result := Default(TIssuedToken);
  Result.Hash := Hash;
  Result.Kind := TTokenKind.Refresh;
  Result.FamilyId := FamilyId;
  Result.UserId := UserId;
  Result.ClientId := 'client-1';
  Result.Scope := 'scope';
  Result.Resource := 'https://resource.example.test';
  Result.CreatedAtUtc := BaseTime;
  Result.ExpiresAtUtc := ExpiresAtUtc;
end;

function TStoreContractTests.NewTokenFor(const Hash, FamilyId, UserId, Resource: string): TIssuedToken;
begin
  Result := NewToken(Hash, FamilyId, UserId, IncDay(BaseTime, 1));
  Result.Resource := Resource;
end;

procedure TStoreContractTests.SavedUserCanBeRead;
begin
  RequireStore;

  var User := Default(TAuthUser);
  User.Id := 'user-1';
  User.DisplayName := 'First User';
  User.CreatedAtUtc := BaseTime;
  FStores.Users.Save(User);

  var Found: TAuthUser;
  const IsFound = FStores.Users.TryGet('user-1', Found);

  Assert.IsTrue(IsFound);
  Assert.AreEqual('user-1', Found.Id);
  Assert.AreEqual('First User', Found.DisplayName);
  Assert.AreEqual(BaseTime, Found.CreatedAtUtc);
end;

procedure TStoreContractTests.UnknownUserIsNotFound;
begin
  RequireStore;

  var Found: TAuthUser;

  const IsFound = FStores.Users.TryGet('nobody', Found);

  Assert.IsFalse(IsFound);
end;

procedure TStoreContractTests.DeletedUserIsNotFound;
begin
  RequireStore;
  SaveUser('user-1');
  SaveUser('user-2');

  FStores.Users.Delete('user-1');

  var Found: TAuthUser;
  Assert.IsFalse(FStores.Users.TryGet('user-1', Found));
  Assert.IsTrue(FStores.Users.TryGet('user-2', Found));
end;

procedure TStoreContractTests.LinkedAccountRoundTrips;
begin
  RequireStore;

  const Expected = NewAccount('user-1', 'object-1');
  FStores.LinkedAccounts.Save(Expected);

  var Actual: TLinkedAccount;
  const IsFound = FStores.LinkedAccounts.TryFind(Expected.UserId, Expected.Key, Actual);

  Assert.IsTrue(IsFound);
  Assert.AreEqual(Expected.Key.Provider, Actual.Key.Provider);
  Assert.AreEqual(Expected.Key.TenantId, Actual.Key.TenantId);
  Assert.AreEqual(Expected.Key.ObjectId, Actual.Key.ObjectId);
  Assert.AreEqual(Expected.UserId, Actual.UserId);
  Assert.AreEqual(Expected.DisplayName, Actual.DisplayName);
  Assert.AreEqual(Expected.UserName, Actual.UserName);
  Assert.AreEqual(Expected.GrantedScopes, Actual.GrantedScopes);
  Assert.AreEqual(Expected.NeedsReconnect, Actual.NeedsReconnect);
  Assert.AreEqual(Expected.LinkedAtUtc, Actual.LinkedAtUtc);
  Assert.AreEqual(Expected.UpdatedAtUtc, Actual.UpdatedAtUtc);
  Assert.AreEqual<TBytes>(Expected.ProtectedRefreshToken, Actual.ProtectedRefreshToken);
end;

procedure TStoreContractTests.SameAccountForTwoUsersAreSeparateRows;
begin
  RequireStore;

  var First := NewAccount('user-1', 'object-1');
  First.DisplayName := 'One';
  First.ProtectedRefreshToken := TBytes.Create(1);
  var Second := NewAccount('user-2', 'object-1');
  Second.DisplayName := 'Two';
  Second.ProtectedRefreshToken := TBytes.Create(2);

  FStores.LinkedAccounts.Save(First);
  FStores.LinkedAccounts.Save(Second);

  var Actual: TLinkedAccount;
  Assert.IsTrue(FStores.LinkedAccounts.TryFind('user-1', First.Key, Actual));
  Assert.AreEqual('One', Actual.DisplayName);
  Assert.AreEqual<TBytes>(TBytes.Create(1), Actual.ProtectedRefreshToken);
  Assert.IsTrue(FStores.LinkedAccounts.TryFind('user-2', First.Key, Actual));
  Assert.AreEqual('Two', Actual.DisplayName);
  Assert.AreEqual<TBytes>(TBytes.Create(2), Actual.ProtectedRefreshToken);
end;

procedure TStoreContractTests.DeleteOfOneUserKeepsTheOtherRow;
begin
  RequireStore;

  const First = NewAccount('user-1', 'object-1');
  FStores.LinkedAccounts.Save(First);
  FStores.LinkedAccounts.Save(NewAccount('user-2', 'object-1'));

  FStores.LinkedAccounts.Delete('user-1', First.Key);

  var Found: TLinkedAccount;
  Assert.IsFalse(FStores.LinkedAccounts.TryFind('user-1', First.Key, Found));
  Assert.IsTrue(FStores.LinkedAccounts.TryFind('user-2', First.Key, Found));
end;

procedure TStoreContractTests.TryFindOfOtherUserIsFalse;
begin
  RequireStore;

  const Account = NewAccount('user-1', 'object-1');
  FStores.LinkedAccounts.Save(Account);

  var Found: TLinkedAccount;
  const IsFound = FStores.LinkedAccounts.TryFind('user-2', Account.Key, Found);

  Assert.IsFalse(IsFound);
end;

procedure TStoreContractTests.ConcurrentSavesOfSameAccountForTwoUsersKeepBothRows;
begin
  RequireStore;

  FFailures := 0;
  var Workers: TArray<TThread>;
  SetLength(Workers, ThreadCount);
  for var Worker := 0 to ThreadCount - 1 do
  begin
    Workers[Worker] := CreateLinkWorker(Worker);
  end;

  for var Worker in Workers do
  begin
    Worker.Start;
  end;
  for var Worker in Workers do
  begin
    Worker.WaitFor;
    Worker.Free;
  end;

  Assert.AreEqual(0, FFailures);
  Assert.AreEqual(1, FStores.LinkedAccounts.ListForUser('user-1').Count);
  Assert.AreEqual(1, FStores.LinkedAccounts.ListForUser('user-2').Count);
end;

procedure TStoreContractTests.ListForUserReturnsOnlyOwnAccounts;
begin
  RequireStore;

  FStores.LinkedAccounts.Save(NewAccount('user-1', 'object-1'));
  FStores.LinkedAccounts.Save(NewAccount('user-1', 'object-2'));
  FStores.LinkedAccounts.Save(NewAccount('user-2', 'object-3'));

  const Accounts = FStores.LinkedAccounts.ListForUser('user-1');

  Assert.AreEqual(2, Accounts.Count);
  for var Account in Accounts do
  begin
    Assert.AreEqual('user-1', Account.UserId);
  end;
end;

procedure TStoreContractTests.DeleteRemovesOnlyThatAccount;
begin
  RequireStore;

  const First = NewAccount('user-1', 'object-1');
  const Second = NewAccount('user-1', 'object-2');
  FStores.LinkedAccounts.Save(First);
  FStores.LinkedAccounts.Save(Second);

  FStores.LinkedAccounts.Delete('user-1', First.Key);

  var Found: TLinkedAccount;
  Assert.IsFalse(FStores.LinkedAccounts.TryFind('user-1', First.Key, Found));
  Assert.IsTrue(FStores.LinkedAccounts.TryFind('user-1', Second.Key, Found));
end;

procedure TStoreContractTests.PendingCanBeReadThenTakenOnce;
begin
  RequireStore;

  FStores.Pending.Put(NewPending('pending-1', IncMinute(BaseTime, 10)));

  var Read: TPendingAuthorization;
  var Taken: TPendingAuthorization;
  var TakenAgain: TPendingAuthorization;
  const CanRead = FStores.Pending.TryGet('pending-1', Read);
  const CanTake = FStores.Pending.TryTake('pending-1', Taken);
  const CanTakeAgain = FStores.Pending.TryTake('pending-1', TakenAgain);

  Assert.IsTrue(CanRead);
  Assert.IsTrue(CanTake);
  Assert.IsFalse(CanTakeAgain);
  Assert.AreEqual('verifier', Taken.UpstreamVerifier);
  Assert.AreEqual('binding-hash', Taken.BrowserBindingHash);
  Assert.AreEqual<TLoginPurpose>(TLoginPurpose.LinkAccount, Taken.Purpose);
end;

procedure TStoreContractTests.ExpiredPendingIsNotTaken;
begin
  RequireStore;

  FStores.Pending.Put(NewPending('pending-1', IncMinute(BaseTime, 10)));
  FFakeClock.AdvanceSeconds(11 * 60);

  var Pending: TPendingAuthorization;
  const CanRead = FStores.Pending.TryGet('pending-1', Pending);
  const CanTake = FStores.Pending.TryTake('pending-1', Pending);

  Assert.IsFalse(CanRead);
  Assert.IsFalse(CanTake);
end;

procedure TStoreContractTests.GrantIsTakenOnce;
begin
  RequireStore;

  FStores.Grants.Put(NewGrant('code-1', IncMinute(BaseTime, 1)));

  var Taken: TAuthorizationGrant;
  var TakenAgain: TAuthorizationGrant;
  const CanTake = FStores.Grants.TryTake('code-1', Taken);
  const CanTakeAgain = FStores.Grants.TryTake('code-1', TakenAgain);

  Assert.IsTrue(CanTake);
  Assert.IsFalse(CanTakeAgain);
  Assert.AreEqual('user-1', Taken.UserId);
  Assert.AreEqual('challenge', Taken.CodeChallenge);
end;

procedure TStoreContractTests.DeleteExpiredRemovesOnlyExpiredPending;
begin
  RequireStore;

  FStores.Pending.Put(NewPending('expired', IncMinute(BaseTime, 5)));
  FStores.Pending.Put(NewPending('valid', IncMinute(BaseTime, 20)));

  const Removed = FStores.Pending.DeleteExpired(IncMinute(BaseTime, 10));

  Assert.AreEqual(1, Removed);
  var Pending: TPendingAuthorization;
  Assert.IsTrue(FStores.Pending.TryGet('valid', Pending));
  Assert.AreEqual(0, FStores.Pending.DeleteExpired(IncMinute(BaseTime, 10)));
end;

procedure TStoreContractTests.DeleteExpiredRemovesOnlyExpiredGrants;
begin
  RequireStore;

  FStores.Grants.Put(NewGrant('expired', IncMinute(BaseTime, 5)));
  FStores.Grants.Put(NewGrant('valid', IncMinute(BaseTime, 20)));

  const Removed = FStores.Grants.DeleteExpired(IncMinute(BaseTime, 10));

  Assert.AreEqual(1, Removed);
  var Grant: TAuthorizationGrant;
  Assert.IsTrue(FStores.Grants.TryTake('valid', Grant));
  Assert.AreEqual(0, FStores.Grants.DeleteExpired(IncMinute(BaseTime, 10)));
end;

procedure TStoreContractTests.ExpiredGrantIsNotTaken;
begin
  RequireStore;

  FStores.Grants.Put(NewGrant('code-1', IncMinute(BaseTime, 1)));
  FFakeClock.AdvanceSeconds(120);

  var Grant: TAuthorizationGrant;
  const CanTake = FStores.Grants.TryTake('code-1', Grant);

  Assert.IsFalse(CanTake);
end;

procedure TStoreContractTests.RefreshTokenIsConsumedOnce;
begin
  RequireStore;

  FStores.Tokens.Save(NewToken('hash-1', 'family-1', 'user-1', IncDay(BaseTime, 1)));

  var Consumed: TIssuedToken;
  var ConsumedAgain: TIssuedToken;
  const CanConsume = FStores.Tokens.TryConsume('hash-1', Consumed);
  const CanConsumeAgain = FStores.Tokens.TryConsume('hash-1', ConsumedAgain);

  Assert.IsTrue(CanConsume);
  Assert.IsFalse(CanConsumeAgain);
  Assert.AreEqual('family-1', Consumed.FamilyId);
end;

procedure TStoreContractTests.ConsumedTokenIsKnownWithFamily;
begin
  RequireStore;

  FStores.Tokens.Save(NewToken('hash-1', 'family-1', 'user-1', IncDay(BaseTime, 1)));
  FStores.Tokens.Save(NewToken('hash-2', 'family-1', 'user-1', IncDay(BaseTime, 1)));
  var Token: TIssuedToken;
  FStores.Tokens.TryConsume('hash-1', Token);

  var FamilyId: string;
  const IsConsumedKnown = FStores.Tokens.IsKnownConsumed('hash-1', FamilyId);
  var OtherFamilyId: string;
  const IsFreshKnown = FStores.Tokens.IsKnownConsumed('hash-2', OtherFamilyId);
  const IsUnknownKnown = FStores.Tokens.IsKnownConsumed('hash-3', OtherFamilyId);

  Assert.IsTrue(IsConsumedKnown);
  Assert.AreEqual('family-1', FamilyId);
  Assert.IsFalse(IsFreshKnown);
  Assert.IsFalse(IsUnknownKnown);
end;

procedure TStoreContractTests.DeleteFamilyRemovesAllTokensOfFamily;
begin
  RequireStore;

  FStores.Tokens.Save(NewToken('hash-1', 'family-1', 'user-1', IncDay(BaseTime, 1)));
  FStores.Tokens.Save(NewToken('hash-2', 'family-1', 'user-1', IncDay(BaseTime, 1)));
  FStores.Tokens.Save(NewToken('hash-3', 'family-2', 'user-1', IncDay(BaseTime, 1)));

  FStores.Tokens.DeleteFamily('family-1');

  var Token: TIssuedToken;
  Assert.IsFalse(FStores.Tokens.TryGet('hash-1', Token));
  Assert.IsFalse(FStores.Tokens.TryGet('hash-2', Token));
  Assert.IsTrue(FStores.Tokens.TryGet('hash-3', Token));
end;

procedure TStoreContractTests.DeleteForUserRemovesAllTokensOfUser;
begin
  RequireStore;

  FStores.Tokens.Save(NewToken('hash-1', 'family-1', 'user-1', IncDay(BaseTime, 1)));
  FStores.Tokens.Save(NewToken('hash-2', 'family-2', 'user-1', IncDay(BaseTime, 1)));
  FStores.Tokens.Save(NewToken('hash-3', 'family-3', 'user-2', IncDay(BaseTime, 1)));

  FStores.Tokens.DeleteForUser('user-1');

  var Token: TIssuedToken;
  Assert.IsFalse(FStores.Tokens.TryGet('hash-1', Token));
  Assert.IsFalse(FStores.Tokens.TryGet('hash-2', Token));
  Assert.IsTrue(FStores.Tokens.TryGet('hash-3', Token));
end;

procedure TStoreContractTests.ListFamiliesForUserGroupsByFamily;
begin
  RequireStore;

  FStores.Tokens.Save(NewTokenFor('hash-1', 'family-1', 'user-1', 'https://a.example.test'));
  FStores.Tokens.Save(NewTokenFor('hash-2', 'family-1', 'user-1', 'https://a.example.test'));
  FStores.Tokens.Save(NewTokenFor('hash-3', 'family-2', 'user-1', 'https://b.example.test'));
  FStores.Tokens.Save(NewTokenFor('hash-4', 'family-3', 'user-2', 'https://a.example.test'));

  const Families = FStores.Tokens.ListFamiliesForUser('user-1');

  Assert.AreEqual(2, Families.Count);
  for var Family in Families do
  begin
    Assert.AreEqual('user-1', Family.UserId);
    Assert.AreEqual('client-1', Family.ClientId);
  end;
end;

procedure TStoreContractTests.HasActiveFamilyIsFalseAfterDeleteFamily;
begin
  RequireStore;

  const Resource = 'https://a.example.test';
  FStores.Tokens.Save(NewTokenFor('hash-1', 'family-1', 'user-1', Resource));
  const IsActiveBefore = FStores.Tokens.HasActiveFamily('user-1', Resource);

  FStores.Tokens.DeleteFamily('family-1');

  const IsActiveAfter = FStores.Tokens.HasActiveFamily('user-1', Resource);
  Assert.IsTrue(IsActiveBefore);
  Assert.IsFalse(IsActiveAfter);
end;

procedure TStoreContractTests.TokensSavedAfterDeleteFamilyStayRevoked;
begin
  RequireStore;

  // A refresh that won TryConsume saves its new pair after a concurrent reuse already revoked the family.
  const Resource = 'https://a.example.test';
  FStores.Tokens.Save(NewTokenFor('hash-1', 'family-1', 'user-1', Resource));
  var Consumed: TIssuedToken;
  Assert.IsTrue(FStores.Tokens.TryConsume('hash-1', Consumed), 'winner consumes');

  FStores.Tokens.DeleteFamily('family-1');
  FStores.Tokens.Save(NewTokenFor('hash-2', 'family-1', 'user-1', Resource));
  FStores.Tokens.Save(NewTokenFor('hash-3', 'family-2', 'user-1', Resource));

  var Token: TIssuedToken;
  Assert.IsFalse(FStores.Tokens.TryGet('hash-2', Token), 'late token is not readable');
  Assert.IsFalse(FStores.Tokens.TryConsume('hash-2', Token), 'late token cannot be refreshed');
  Assert.IsTrue(FStores.Tokens.TryGet('hash-3', Token), 'other family unaffected');

  const Families = FStores.Tokens.ListFamiliesForUser('user-1');
  Assert.AreEqual(1, Families.Count);
  Assert.AreEqual('family-2', Families[0].FamilyId);

  FStores.Tokens.DeleteFamily('family-2');
  Assert.IsFalse(FStores.Tokens.HasActiveFamily('user-1', Resource), 'no active family left');
end;

procedure TStoreContractTests.DeleteExpiredForgetsOldRevocationsWithoutTokens;
begin
  RequireStore;

  FStores.Tokens.DeleteFamily('family-1');
  FStores.Tokens.DeleteExpired(IncHour(BaseTime, 1));

  var Token: TIssuedToken;
  FStores.Tokens.Save(NewToken('hash-1', 'family-1', 'user-1', IncDay(BaseTime, 3)));
  Assert.IsFalse(FStores.Tokens.TryGet('hash-1', Token), 'a fresh revocation is kept');

  FStores.Tokens.DeleteFamily('family-2');
  FStores.Tokens.DeleteExpired(IncDay(BaseTime, 2));

  FStores.Tokens.Save(NewToken('hash-2', 'family-2', 'user-1', IncDay(BaseTime, 3)));
  Assert.IsTrue(FStores.Tokens.TryGet('hash-2', Token), 'a revocation older than a day without tokens is forgotten');
  Assert.IsFalse(FStores.Tokens.TryGet('hash-1', Token), 'a revocation with tokens left is kept');
end;

procedure TStoreContractTests.DeleteExpiredRemovesOnlyExpired;
begin
  RequireStore;

  FStores.Tokens.Save(NewToken('expired', 'family-1', 'user-1', IncMinute(BaseTime, 5)));
  FStores.Tokens.Save(NewToken('valid', 'family-2', 'user-1', IncDay(BaseTime, 1)));

  const Removed = FStores.Tokens.DeleteExpired(IncMinute(BaseTime, 10));

  Assert.AreEqual(1, Removed);
  var Token: TIssuedToken;
  Assert.IsTrue(FStores.Tokens.TryGet('valid', Token));
  Assert.AreEqual(0, FStores.Tokens.DeleteExpired(IncMinute(BaseTime, 10)));
end;

procedure TStoreContractTests.ExpiredSessionIsNotFound;
begin
  RequireStore;

  var Session := Default(TWebSession);
  Session.IdHash := 'session-1';
  Session.UserId := 'user-1';
  Session.CsrfToken := 'csrf';
  Session.ExpiresAtUtc := IncMinute(BaseTime, 30);
  FStores.Sessions.Put(Session);

  var Found: TWebSession;
  const IsFoundBefore = FStores.Sessions.TryGet('session-1', Found);
  FFakeClock.AdvanceSeconds(31 * 60);
  const IsFoundAfter = FStores.Sessions.TryGet('session-1', Found);

  Assert.IsTrue(IsFoundBefore);
  Assert.IsFalse(IsFoundAfter);
end;

procedure TStoreContractTests.ClientRoundTrips;
begin
  RequireStore;

  var Expected := Default(TOAuthClient);
  Expected.ClientId := 'client-1';
  Expected.ClientName := 'Client One';
  Expected.RedirectUris := ['https://client.example.test/callback', 'http://127.0.0.1:33418/callback'];
  Expected.CreatedAtUtc := BaseTime;
  FStores.Clients.Save(Expected);

  var Actual: TOAuthClient;
  const IsFound = FStores.Clients.TryGet('client-1', Actual);
  var Unknown: TOAuthClient;
  const IsUnknownFound = FStores.Clients.TryGet('client-2', Unknown);

  Assert.IsTrue(IsFound);
  Assert.IsFalse(IsUnknownFound);
  Assert.AreEqual(Expected.ClientName, Actual.ClientName);
  Assert.AreEqual(Expected.CreatedAtUtc, Actual.CreatedAtUtc);
  Assert.AreEqual<Integer>(2, Length(Actual.RedirectUris));
  Assert.AreEqual(Expected.RedirectUris[0], Actual.RedirectUris[0]);
  Assert.AreEqual(Expected.RedirectUris[1], Actual.RedirectUris[1]);
end;

procedure TStoreContractTests.RemovedSessionIsNotFound;
begin
  RequireStore;

  var Session := Default(TWebSession);
  Session.IdHash := 'session-1';
  Session.UserId := 'user-1';
  Session.CsrfToken := 'csrf';
  Session.ExpiresAtUtc := IncMinute(BaseTime, 30);
  FStores.Sessions.Put(Session);

  FStores.Sessions.Remove('session-1');

  var Found: TWebSession;
  const IsFound = FStores.Sessions.TryGet('session-1', Found);
  Assert.IsFalse(IsFound);
  Assert.AreEqual(0, FStores.Sessions.DeleteExpired(IncHour(BaseTime, 1)));
end;

procedure TStoreContractTests.RunWorker(const Worker: Integer);
begin
  try
    for var SaveIndex := 0 to SavesPerThread - 1 do
    begin
      const Id = Format('%d-%d', [Worker, SaveIndex]);
      FStores.Tokens.Save(NewToken('token-' + Id, 'family-' + Id, 'user-' + Id, IncDay(BaseTime, 1)));
      FStores.Pending.Put(NewPending('pending-' + Id, IncDay(BaseTime, 1)));
    end;

    var Consumed: TIssuedToken;
    if FStores.Tokens.TryConsume(SharedTokenHash, Consumed) then
    begin
      TInterlocked.Increment(FConsumeSuccesses);
    end;
  except
    TInterlocked.Increment(FFailures);
  end;
end;

function TStoreContractTests.CreateWorker(const Worker: Integer): TThread;
begin
  Result := TThread.CreateAnonymousThread(
    procedure
    begin
      RunWorker(Worker);
    end);
  Result.FreeOnTerminate := False;
end;

procedure TStoreContractTests.RunLinkWorker(const Worker: Integer);
begin
  try
    const UserId = Format('user-%d', [1 + (Worker mod 2)]);
    for var SaveIndex := 0 to LinkSavesPerThread - 1 do
    begin
      FStores.LinkedAccounts.Save(NewAccount(UserId, 'object-shared'));
    end;
  except
    TInterlocked.Increment(FFailures);
  end;
end;

function TStoreContractTests.CreateLinkWorker(const Worker: Integer): TThread;
begin
  Result := TThread.CreateAnonymousThread(
    procedure
    begin
      RunLinkWorker(Worker);
    end);
  Result.FreeOnTerminate := False;
end;

function TStoreContractTests.CountMissingKeys: Integer;
begin
  Result := 0;
  for var Worker := 0 to ThreadCount - 1 do
  begin
    for var SaveIndex := 0 to SavesPerThread - 1 do
    begin
      const Id = Format('%d-%d', [Worker, SaveIndex]);
      var Token: TIssuedToken;
      var Pending: TPendingAuthorization;
      const IsComplete = (FStores.Tokens.TryGet('token-' + Id, Token) and
                          FStores.Pending.TryGet('pending-' + Id, Pending));
      if not IsComplete then
      begin
        Inc(Result);
      end;
    end;
  end;
end;

procedure TStoreContractTests.ConcurrentSavesAreSafe;
begin
  RequireStore;

  FStores.Tokens.Save(NewToken(SharedTokenHash, 'family-shared', 'user-shared', IncDay(BaseTime, 1)));
  FConsumeSuccesses := 0;
  FFailures := 0;
  var Workers: TArray<TThread>;
  SetLength(Workers, ThreadCount);
  for var Worker := 0 to ThreadCount - 1 do
  begin
    Workers[Worker] := CreateWorker(Worker);
  end;

  for var Worker in Workers do
  begin
    Worker.Start;
  end;
  for var Worker in Workers do
  begin
    Worker.WaitFor;
    Worker.Free;
  end;

  Assert.AreEqual(0, FFailures);
  Assert.AreEqual(1, FConsumeSuccesses);
  Assert.AreEqual(0, CountMissingKeys);
end;

procedure TStoreContractTests.UserWithNonAsciiNameRoundTrips;
begin
  RequireStore;

  var User := Default(TAuthUser);
  User.Id := 'user-1';
  User.DisplayName := LatinName;
  User.CreatedAtUtc := BaseTime;
  FStores.Users.Save(User);

  var Found: TAuthUser;
  const IsFound = FStores.Users.TryGet('user-1', Found);

  Assert.IsTrue(IsFound);
  Assert.AreEqual(LatinName, Found.DisplayName);
end;

procedure TStoreContractTests.LinkedAccountWithNonAsciiNamesRoundTrips;
begin
  RequireStore;

  var Expected := NewAccount('user-1', 'object-1');
  Expected.DisplayName := LatinName;
  Expected.UserName := MixedName + '@example.test';
  FStores.LinkedAccounts.Save(Expected);

  var Actual: TLinkedAccount;
  const IsFound = FStores.LinkedAccounts.TryFind(Expected.UserId, Expected.Key, Actual);

  Assert.IsTrue(IsFound);
  Assert.AreEqual(LatinName, Actual.DisplayName);
  Assert.AreEqual(Expected.UserName, Actual.UserName);
end;

procedure TStoreContractTests.ClientWithNonAsciiNameRoundTrips;
begin
  RequireStore;

  var Expected := Default(TOAuthClient);
  Expected.ClientId := 'client-1';
  Expected.ClientName := MixedName;
  Expected.RedirectUris := ['https://client.example.test/callback'];
  Expected.CreatedAtUtc := BaseTime;
  FStores.Clients.Save(Expected);

  var Actual: TOAuthClient;
  const IsFound = FStores.Clients.TryGet('client-1', Actual);

  Assert.IsTrue(IsFound);
  Assert.AreEqual(MixedName, Actual.ClientName);
end;

procedure TStoreContractTests.LoginIdentityRoundTrips;
begin
  RequireStore;
  SaveUser('user-1');

  const Expected = NewIdentity('user-1', 'tenant-1', 'object-1');
  FStores.LoginIdentities.Save(Expected);

  var Actual: TLoginIdentity;
  const IsFound = FStores.LoginIdentities.TryFind(Expected.Key, Actual);

  Assert.IsTrue(IsFound);
  Assert.AreEqual(Expected.Key.Provider, Actual.Key.Provider);
  Assert.AreEqual(Expected.Key.TenantId, Actual.Key.TenantId);
  Assert.AreEqual(Expected.Key.ObjectId, Actual.Key.ObjectId);
  Assert.AreEqual(Expected.UserId, Actual.UserId);
  Assert.AreEqual(Expected.UserName, Actual.UserName);
  Assert.AreEqual(Expected.CreatedAtUtc, Actual.CreatedAtUtc);
  Assert.AreEqual(Expected.LastLoginAtUtc, Actual.LastLoginAtUtc);
end;

procedure TStoreContractTests.IdentityIsFoundRegardlessOfKeyCase;
begin
  RequireStore;
  SaveUser('user-1');
  FStores.LoginIdentities.Save(NewIdentity('user-1', 'Tenant-A', 'object-1'));

  var Actual: TLoginIdentity;
  const IsFound = FStores.LoginIdentities.TryFind(NewIdentity('user-1', 'tenant-a', 'object-1').Key, Actual);

  Assert.IsTrue(IsFound);
  Assert.AreEqual('user-1', Actual.UserId);
end;

procedure TStoreContractTests.SavingIdentityOfOtherUserRaises;
begin
  RequireStore;
  SaveUser('user-1');
  SaveUser('user-2');
  const Original = NewIdentity('user-1', 'tenant-1', 'object-1');
  FStores.LoginIdentities.Save(Original);
  const Hijack = NewIdentity('user-2', 'tenant-1', 'object-1');

  Assert.WillRaise(
    procedure
    begin
      FStores.LoginIdentities.Save(Hijack);
    end,
    ELoginIdentityTaken);

  var Actual: TLoginIdentity;
  Assert.IsTrue(FStores.LoginIdentities.TryFind(Original.Key, Actual));
  Assert.AreEqual('user-1', Actual.UserId);
end;

procedure TStoreContractTests.SavingOwnIdentityAgainUpdatesIt;
begin
  RequireStore;
  SaveUser('user-1');
  const Original = NewIdentity('user-1', 'tenant-1', 'object-1');
  FStores.LoginIdentities.Save(Original);
  var Later := Original;
  Later.LastLoginAtUtc := IncDay(BaseTime, 3);

  FStores.LoginIdentities.Save(Later);

  var Actual: TLoginIdentity;
  Assert.IsTrue(FStores.LoginIdentities.TryFind(Original.Key, Actual));
  Assert.AreEqual(IncDay(BaseTime, 3), Actual.LastLoginAtUtc);
  Assert.AreEqual(BaseTime, Actual.CreatedAtUtc);
end;

procedure TStoreContractTests.ListIdentitiesForUserReturnsOnlyOwn;
begin
  RequireStore;
  SaveUser('user-1');
  SaveUser('user-2');
  FStores.LoginIdentities.Save(NewIdentity('user-1', 'tenant-1', 'object-1'));
  FStores.LoginIdentities.Save(NewIdentity('user-2', 'tenant-1', 'object-2'));

  const Identities = FStores.LoginIdentities.ListForUser('user-1');

  Assert.AreEqual(1, Identities.Count);
  Assert.AreEqual('object-1', Identities[0].Key.ObjectId);
end;

end.
