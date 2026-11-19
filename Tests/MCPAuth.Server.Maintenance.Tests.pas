unit MCPAuth.Server.Maintenance.Tests;

interface

uses
  DUnitX.TestFramework,
  MCPAuth.Fakes.Clock,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Store.Interfaces;

type
  [TestFixture]
  TServerMaintenanceTests = class
  private
    FClock: TFakeClock;
    FClockReference: IClock;
    FStores: TStoreSet;
    FStartUtc: TDateTime;

    procedure SaveToken(const Hash: string; const LifetimeSeconds: Integer);
    procedure SaveSession(const IdHash: string; const LifetimeSeconds: Integer);
    function HasToken(const Hash: string): Boolean;
    function HasSession(const IdHash: string): Boolean;

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure MaintenanceDeletesExpiredTokens;

    [Test]
    procedure MaintenanceDeletesExpiredSessions;

    [Test]
    procedure MaintenanceDeletesExpiredPendingAndGrants;

    [Test]
    procedure MaintenanceRunsOnItsInterval;

    [Test]
    procedure MaintenanceStopsPromptly;
  end;

implementation

uses
  System.SysUtils,
  System.DateUtils,
  System.Diagnostics,
  MCPAuth.Store.Memory,
  MCPAuth.OAuth.Types,
  MCPAuth.Web.Types,
  MCPAuth.Server.Maintenance;

const
  OneMinute = 60;
  TwoMinutes = 120;
  OneHour = 3600;
  ShortIntervalMs = 20;
  WaitStepMs = 10;
  MaxWaitMs = 2000;
  PromptStopMs = 2000;

{ TServerMaintenanceTests }

procedure TServerMaintenanceTests.Setup;
begin
  FStartUtc := EncodeDateTime(2026, 1, 2, 3, 4, 5, 0);
  FClock := TFakeClock.Create(FStartUtc);
  FClockReference := FClock;
  FStores := TMemoryStore.CreateSet(FClockReference);
end;

procedure TServerMaintenanceTests.TearDown;
begin
  FStores := Default(TStoreSet);
  FClockReference := nil;
end;

procedure TServerMaintenanceTests.SaveToken(const Hash: string; const LifetimeSeconds: Integer);
begin
  var Token := Default(TIssuedToken);
  Token.Hash         := Hash;
  Token.Kind         := TTokenKind.Access;
  Token.FamilyId     := 'family-1';
  Token.UserId       := 'user-1';
  Token.ClientId     := 'client-1';
  Token.Scope        := 'mcp';
  Token.Resource     := 'https://a.example.test/mcp';
  Token.CreatedAtUtc := FStartUtc;
  Token.ExpiresAtUtc := IncSecond(FStartUtc, LifetimeSeconds);
  FStores.Tokens.Save(Token);
end;

procedure TServerMaintenanceTests.SaveSession(const IdHash: string; const LifetimeSeconds: Integer);
begin
  var Session := Default(TWebSession);
  Session.IdHash       := IdHash;
  Session.UserId       := 'user-1';
  Session.CsrfToken    := 'csrf';
  Session.ExpiresAtUtc := IncSecond(FStartUtc, LifetimeSeconds);
  FStores.Sessions.Put(Session);
end;

function TServerMaintenanceTests.HasToken(const Hash: string): Boolean;
begin
  // Looked up at the start time, where an expired token still counts as present unless it was deleted.
  FClock.SetNowUtc(FStartUtc);
  var Token: TIssuedToken;
  Result := FStores.Tokens.TryGet(Hash, Token);
end;

function TServerMaintenanceTests.HasSession(const IdHash: string): Boolean;
begin
  FClock.SetNowUtc(FStartUtc);
  var Session: TWebSession;
  Result := FStores.Sessions.TryGet(IdHash, Session);
end;

procedure TServerMaintenanceTests.MaintenanceDeletesExpiredTokens;
begin
  SaveToken('expired', OneMinute);
  SaveToken('valid', OneHour);
  const Maintenance = TServerMaintenance.Create(FStores, FClockReference);
  try
    FClock.AdvanceSeconds(TwoMinutes);

    Maintenance.RunOnce;

    Assert.IsFalse(HasToken('expired'));
    Assert.IsTrue(HasToken('valid'));
  finally
    Maintenance.Free;
  end;
end;

procedure TServerMaintenanceTests.MaintenanceDeletesExpiredSessions;
begin
  SaveSession('expired', OneMinute);
  SaveSession('valid', OneHour);
  const Maintenance = TServerMaintenance.Create(FStores, FClockReference);
  try
    FClock.AdvanceSeconds(TwoMinutes);

    Maintenance.RunOnce;

    Assert.IsFalse(HasSession('expired'));
    Assert.IsTrue(HasSession('valid'));
  finally
    Maintenance.Free;
  end;
end;

procedure TServerMaintenanceTests.MaintenanceDeletesExpiredPendingAndGrants;
begin
  var Pending := Default(TPendingAuthorization);
  Pending.Id           := 'pending-1';
  Pending.ExpiresAtUtc := IncSecond(FStartUtc, OneMinute);
  FStores.Pending.Put(Pending);

  var Grant := Default(TAuthorizationGrant);
  Grant.CodeHash     := 'code-1';
  Grant.ExpiresAtUtc := IncSecond(FStartUtc, OneMinute);
  FStores.Grants.Put(Grant);

  const Maintenance = TServerMaintenance.Create(FStores, FClockReference);
  try
    FClock.AdvanceSeconds(TwoMinutes);

    Maintenance.RunOnce;

    Assert.AreEqual(0, FStores.Pending.DeleteExpired(FClock.NowUtc), 'pending already deleted');
    Assert.AreEqual(0, FStores.Grants.DeleteExpired(FClock.NowUtc), 'grant already deleted');
  finally
    Maintenance.Free;
  end;
end;

procedure TServerMaintenanceTests.MaintenanceRunsOnItsInterval;
begin
  SaveToken('expired', OneMinute);
  FClock.AdvanceSeconds(TwoMinutes);
  const Maintenance = TServerMaintenance.Create(FStores, FClockReference, ShortIntervalMs);
  try
    Maintenance.Start;

    const Watch = TStopwatch.StartNew;
    while (Maintenance.RunCount = 0) and (Watch.ElapsedMilliseconds < MaxWaitMs) do
    begin
      Sleep(WaitStepMs);
    end;
    Maintenance.Stop;

    Assert.IsTrue(Maintenance.RunCount > 0, 'the thread ran at least once');
    Assert.IsFalse(HasToken('expired'));
  finally
    Maintenance.Free;
  end;
end;

procedure TServerMaintenanceTests.MaintenanceStopsPromptly;
begin
  const Maintenance = TServerMaintenance.Create(FStores, FClockReference);
  try
    Maintenance.Start;
    Sleep(WaitStepMs);

    const Watch = TStopwatch.StartNew;
    Maintenance.Stop;
    const ElapsedMs = Watch.ElapsedMilliseconds;

    Assert.IsTrue(ElapsedMs < PromptStopMs, Format('Stop took %d ms', [ElapsedMs]));
  finally
    Maintenance.Free;
  end;
end;

end.
