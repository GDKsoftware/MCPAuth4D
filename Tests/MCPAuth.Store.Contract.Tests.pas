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
    function NewPending(const Id: string; const ExpiresAtUtc: TDateTime): TPendingAuthorization;
    function NewGrant(const CodeHash: string; const ExpiresAtUtc: TDateTime): TAuthorizationGrant;
    function NewToken(const Hash, FamilyId, UserId: string; const ExpiresAtUtc: TDateTime): TIssuedToken;
    function NewTokenFor(const Hash, FamilyId, UserId, Resource: string): TIssuedToken;

    procedure RunWorker(const Worker: Integer);
    function CreateWorker(const Worker: Integer): TThread;
    function CountMissingKeys: Integer;

  protected
    function CreateStore(const Clock: IClock): TStoreSet; virtual; abstract;

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
    procedure LinkedAccountRoundTrips;

    [Test]
    procedure SavingKeyOfOtherUserRaises;

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
    procedure DeleteExpiredRemovesOnlyExpired;

    [Test]
    procedure ExpiredSessionIsNotFound;

    [Test]
    procedure ConcurrentSavesAreSafe;
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
  SharedTokenHash = 'shared-token';

{ TStoreContractTests }

procedure TStoreContractTests.Setup;
begin
  FFakeClock := TFakeClock.Create(BaseTime);
  FClock := FFakeClock;
  FStores := CreateStore(FClock);
end;

procedure TStoreContractTests.TearDown;
begin
  FStores := Default(TStoreSet);
  FClock := nil;
  FFakeClock := nil;
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
  var Found: TAuthUser;

  const IsFound = FStores.Users.TryGet('nobody', Found);

  Assert.IsFalse(IsFound);
end;

procedure TStoreContractTests.LinkedAccountRoundTrips;
begin
  const Expected = NewAccount('user-1', 'object-1');
  FStores.LinkedAccounts.Save(Expected);

  var Actual: TLinkedAccount;
  const IsFound = FStores.LinkedAccounts.TryFind(Expected.Key, Actual);

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

procedure TStoreContractTests.SavingKeyOfOtherUserRaises;
begin
  const Original = NewAccount('user-1', 'object-1');
  FStores.LinkedAccounts.Save(Original);
  var Hijack := NewAccount('user-2', 'object-1');
  Hijack.DisplayName := 'Hijacked';

  Assert.WillRaise(
    procedure
    begin
      FStores.LinkedAccounts.Save(Hijack);
    end,
    EAccountLinkedToOtherUser);

  var Actual: TLinkedAccount;
  Assert.IsTrue(FStores.LinkedAccounts.TryFind(Original.Key, Actual));
  Assert.AreEqual('user-1', Actual.UserId);
  Assert.AreEqual(Original.DisplayName, Actual.DisplayName);
end;

procedure TStoreContractTests.ListForUserReturnsOnlyOwnAccounts;
begin
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
  const First = NewAccount('user-1', 'object-1');
  const Second = NewAccount('user-1', 'object-2');
  FStores.LinkedAccounts.Save(First);
  FStores.LinkedAccounts.Save(Second);

  FStores.LinkedAccounts.Delete('user-1', First.Key);

  var Found: TLinkedAccount;
  Assert.IsFalse(FStores.LinkedAccounts.TryFind(First.Key, Found));
  Assert.IsTrue(FStores.LinkedAccounts.TryFind(Second.Key, Found));
end;

procedure TStoreContractTests.PendingCanBeReadThenTakenOnce;
begin
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
  Assert.AreEqual<TLoginPurpose>(TLoginPurpose.LinkAccount, Taken.Purpose);
end;

procedure TStoreContractTests.ExpiredPendingIsNotTaken;
begin
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

procedure TStoreContractTests.ExpiredGrantIsNotTaken;
begin
  FStores.Grants.Put(NewGrant('code-1', IncMinute(BaseTime, 1)));
  FFakeClock.AdvanceSeconds(120);

  var Grant: TAuthorizationGrant;
  const CanTake = FStores.Grants.TryTake('code-1', Grant);

  Assert.IsFalse(CanTake);
end;

procedure TStoreContractTests.RefreshTokenIsConsumedOnce;
begin
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
  const Resource = 'https://a.example.test';
  FStores.Tokens.Save(NewTokenFor('hash-1', 'family-1', 'user-1', Resource));
  const IsActiveBefore = FStores.Tokens.HasActiveFamily('user-1', Resource);

  FStores.Tokens.DeleteFamily('family-1');

  const IsActiveAfter = FStores.Tokens.HasActiveFamily('user-1', Resource);
  Assert.IsTrue(IsActiveBefore);
  Assert.IsFalse(IsActiveAfter);
end;

procedure TStoreContractTests.DeleteExpiredRemovesOnlyExpired;
begin
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

end.
