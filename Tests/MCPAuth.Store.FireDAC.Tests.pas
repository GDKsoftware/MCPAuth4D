unit MCPAuth.Store.FireDAC.Tests;

interface

uses
  DUnitX.TestFramework,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Store.Interfaces,
  MCPAuth.Store.Contract.Tests,
  MCPAuth.Store.FireDAC.Interfaces,
  MCPAuth.Store.FireDAC.PgDriver;

type
  // Runs the store contract against PostgreSQL. Without MCPAUTH_TEST_PG every test passes without a database.
  [TestFixture]
  TFireDACStoreContractTests = class(TStoreContractTests)
  private
    FDriver: TFireDACPgDriver;
    FFactory: IFireDACConnectionFactory;

    procedure RecreateSchema;
    procedure ClearTables;
    procedure AssertStoredAsUtc(const Factory: IFireDACConnectionFactory);
    procedure DropSchema;
    procedure CopyMigrations(const TargetPath: string; const UpToVersion: Integer);
    procedure InsertUserWithAccount(const UserId, ObjectId, LinkedAt: string);
    procedure InsertAccount(const UserId, ObjectId, LinkedAt: string);
    function IdentityKeyOf(const UserId: string): string;

  protected
    function CreateStore(const Clock: IClock): TStoreSet; override;
    function UnavailableReason: string; override;

  public
    [SetupFixture]
    procedure SetupFixture;

    [TearDownFixture]
    procedure TearDownFixture;

    [Test]
    procedure TimesAreStoredAsUtc;

    [Test]
    procedure TimesStayUtcInAnotherSessionTimeZone;

    [Test]
    procedure AddMissingGivesUsersWithoutIdentityTheirOldestAccount;

    [Test]
    procedure AddMissingSkipsAccountLinkedByOtherUser;

    [Test]
    procedure AddMissingIgnoresLinksWithoutUser;

    [Test]
    procedure Migration0004GivesExistingUsersTheirOldestAccount;
  end;

implementation

uses
  System.SysUtils,
  System.IOUtils,
  System.DateUtils,
  MCPAuth.Fakes.Clock,
  MCPAuth.OAuth.Types,
  MCPAuth.Store.FireDAC,
  MCPAuth.Store.FireDAC.ConnectionFactory,
  MCPAuth.Store.FireDAC.LoginIdentities,
  MCPAuth.Store.FireDAC.Migrations,
  MCPAuth.Tests.Postgres;

const
  // Child tables first: mcpauth_login_identities refers to mcpauth_users.
  StoreTables: array[0..8] of string = ('mcpauth_login_identities', 'mcpauth_users', 'mcpauth_linked_accounts', 'mcpauth_clients', 'mcpauth_pending_authorizations',
                                        'mcpauth_grants', 'mcpauth_tokens', 'mcpauth_sessions', 'mcpauth_revoked_families');
  VersionTable = 'mcpauth_schema_version';
  UtcTokenHash = 'utc-token';
  // 2026-06-01 12:00:00 UTC
  UtcExpiryUnix = 1780315200;
  InsertTestUser = 'INSERT INTO mcpauth_users (id, display_name, created_at) VALUES (''%0:s'', ''%0:s'', ''%1:s'') ON CONFLICT (id) DO NOTHING';
  InsertTestAccount = 'INSERT INTO mcpauth_linked_accounts (account_key, provider, tenant_id, object_id, user_id, display_name, user_name, ' +
                      'granted_scopes, protected_refresh_token, needs_reconnect, linked_at, updated_at) VALUES (''microsoft:tenant-1:%0:s'', ' +
                      '''microsoft'', ''tenant-1'', ''%0:s'', ''%1:s'', ''%0:s'', ''%0:s@example.test'', ''openid'', ''\x00'', false, ''%2:s'', ''%2:s'')';

{ TFireDACStoreContractTests }

procedure TFireDACStoreContractTests.SetupFixture;
begin
  if not UnavailableReason.IsEmpty then
  begin
    Exit;
  end;

  FDriver := TFireDACPgDriver.Create(TTestPostgres.VendorLib);
  try
    FFactory := TFireDACConnectionFactory.Create(TTestPostgres.ConnectionString);
    RecreateSchema;
  except
    // DUnitX skips the fixture teardown when its setup fails.
    TearDownFixture;
    raise;
  end;
end;

procedure TFireDACStoreContractTests.TearDownFixture;
begin
  FFactory := nil;
  FreeAndNil(FDriver);
end;

function TFireDACStoreContractTests.UnavailableReason: string;
begin
  Result := TTestPostgres.UnavailableReason;
end;

function TFireDACStoreContractTests.CreateStore(const Clock: IClock): TStoreSet;
begin
  ClearTables;
  Result := TFireDACStore.CreateSet(FFactory, Clock);
end;

procedure TFireDACStoreContractTests.RecreateSchema;
begin
  DropSchema;
  TFireDACMigrations.Apply(FFactory, 'postgres', TTestPostgres.MigrationsPath);
end;

procedure TFireDACStoreContractTests.DropSchema;
begin
  for var Table in StoreTables do
  begin
    TTestPostgres.Execute(FFactory, Format('DROP TABLE IF EXISTS %s', [Table]));
  end;
  TTestPostgres.Execute(FFactory, Format('DROP TABLE IF EXISTS %s', [VersionTable]));
end;

procedure TFireDACStoreContractTests.ClearTables;
begin
  for var Table in StoreTables do
  begin
    TTestPostgres.Execute(FFactory, Format('DELETE FROM %s', [Table]));
  end;
end;

procedure TFireDACStoreContractTests.TimesAreStoredAsUtc;
begin
  RequireStore;

  ClearTables;
  AssertStoredAsUtc(FFactory);
end;

procedure TFireDACStoreContractTests.TimesStayUtcInAnotherSessionTimeZone;
begin
  RequireStore;

  ClearTables;
  const OtherZone = TTestPostgres.ConnectionString + ';PGAdvanced=options=-c TimeZone=Asia/Kathmandu';
  const Factory: IFireDACConnectionFactory = TFireDACConnectionFactory.Create(OtherZone);
  Assert.AreEqual<Int64>(0, TTestPostgres.QueryInt(Factory, 'SELECT CASE WHEN current_setting(''TimeZone'') = ''Asia/Kathmandu'' THEN 0 ELSE 1 END'));

  AssertStoredAsUtc(Factory);
end;

procedure TFireDACStoreContractTests.AssertStoredAsUtc(const Factory: IFireDACConnectionFactory);
begin
  const ExpiresAtUtc = UnixToDateTime(UtcExpiryUnix, True);
  const Clock: IClock = TFakeClock.Create(IncDay(ExpiresAtUtc, -1));
  const Stores = TFireDACStore.CreateSet(Factory, Clock);
  var Token := Default(TIssuedToken);
  Token.Hash := UtcTokenHash;
  Token.Kind := TTokenKind.Refresh;
  Token.FamilyId := 'family-utc';
  Token.UserId := 'user-utc';
  Token.CreatedAtUtc := Clock.NowUtc;
  Token.ExpiresAtUtc := ExpiresAtUtc;
  Stores.Tokens.Save(Token);

  var Read: TIssuedToken;
  const IsFound = Stores.Tokens.TryGet(UtcTokenHash, Read);
  const StoredUnix = TTestPostgres.QueryInt(Factory, Format('SELECT CAST(EXTRACT(EPOCH FROM expires_at) AS bigint) FROM mcpauth_tokens WHERE hash = ''%s''', [UtcTokenHash]));

  Assert.IsTrue(IsFound);
  Assert.AreEqual<TDateTime>(ExpiresAtUtc, Read.ExpiresAtUtc);
  Assert.AreEqual<Int64>(UtcExpiryUnix, StoredUnix);
end;

procedure TFireDACStoreContractTests.AddMissingGivesUsersWithoutIdentityTheirOldestAccount;
begin
  RequireStore;

  ClearTables;
  InsertUserWithAccount('u1', 'object-newer', '2026-06-02 10:00:00+00');
  InsertUserWithAccount('u1', 'object-older', '2026-06-01 10:00:00+00');
  const Identities = TFireDACLoginIdentityRepository.Create(FFactory);
  try
    const FirstRun = Identities.AddMissing;
    const SecondRun = Identities.AddMissing;

    Assert.AreEqual(1, FirstRun);
    Assert.AreEqual(0, SecondRun);
    Assert.AreEqual('microsoft:tenant-1:object-older', IdentityKeyOf('u1'));
  finally
    Identities.Free;
  end;
end;

procedure TFireDACStoreContractTests.AddMissingSkipsAccountLinkedByOtherUser;
begin
  RequireStore;

  ClearTables;
  InsertUserWithAccount('u1', 'object-shared', '2026-06-01 10:00:00+00');
  InsertUserWithAccount('u2', 'object-shared', '2026-06-02 10:00:00+00');
  const Identities = TFireDACLoginIdentityRepository.Create(FFactory);
  try
    const Added = Identities.AddMissing;

    Assert.AreEqual(0, Added);
    Assert.AreEqual<Int64>(0, TTestPostgres.QueryInt(FFactory, 'SELECT COUNT(*) FROM mcpauth_login_identities'));
  finally
    Identities.Free;
  end;
end;

procedure TFireDACStoreContractTests.AddMissingIgnoresLinksWithoutUser;
begin
  RequireStore;

  ClearTables;
  InsertAccount('ghost', 'object-ghost', '2026-06-01 10:00:00+00');
  const Identities = TFireDACLoginIdentityRepository.Create(FFactory);
  try
    const Added = Identities.AddMissing;

    Assert.AreEqual(0, Added);
  finally
    Identities.Free;
  end;
end;

procedure TFireDACStoreContractTests.Migration0004GivesExistingUsersTheirOldestAccount;
begin
  RequireStore;

  const MigrationsPath = TPath.Combine(TPath.GetTempPath, 'mcpauth-0004-' + TGUID.NewGuid.ToString);
  try
    DropSchema;
    CopyMigrations(MigrationsPath, 3);
    TFireDACMigrations.Apply(FFactory, 'postgres', MigrationsPath);
    InsertUserWithAccount('u1', 'object-a', '2026-06-01 10:00:00+00');
    InsertUserWithAccount('u2', 'object-c', '2026-06-03 10:00:00+00');
    InsertUserWithAccount('u2', 'object-b', '2026-06-02 10:00:00+00');
    InsertAccount('ghost', 'object-ghost', '2026-06-01 09:00:00+00');

    CopyMigrations(MigrationsPath, 4);
    TFireDACMigrations.Apply(FFactory, 'postgres', MigrationsPath);

    Assert.AreEqual<Int64>(2, TTestPostgres.QueryInt(FFactory, 'SELECT COUNT(*) FROM mcpauth_login_identities'));
    Assert.AreEqual('microsoft:tenant-1:object-a', IdentityKeyOf('u1'));
    Assert.AreEqual('microsoft:tenant-1:object-b', IdentityKeyOf('u2'));
    Assert.AreEqual<Int64>(4, TTestPostgres.QueryInt(FFactory, 'SELECT COUNT(*) FROM mcpauth_linked_accounts'));

    InsertUserWithAccount('u2', 'object-a', '2026-06-04 10:00:00+00');
    Assert.AreEqual<Int64>(2, TTestPostgres.QueryInt(FFactory, 'SELECT COUNT(*) FROM mcpauth_linked_accounts WHERE object_id = ''object-a'''));
  finally
    TDirectory.Delete(MigrationsPath, True);
    RecreateSchema;
  end;
end;

procedure TFireDACStoreContractTests.CopyMigrations(const TargetPath: string; const UpToVersion: Integer);
begin
  const SourceFolder = TPath.Combine(TTestPostgres.MigrationsPath, 'postgres');
  const TargetFolder = TPath.Combine(TargetPath, 'postgres');
  TDirectory.CreateDirectory(TargetFolder);
  for var Source in TDirectory.GetFiles(SourceFolder, '*.sql') do
  begin
    const FileName = TPath.GetFileName(Source);
    const Target = TPath.Combine(TargetFolder, FileName);
    const IsWanted = ((StrToInt(FileName.Substring(0, 4)) <= UpToVersion) and not TFile.Exists(Target));
    if IsWanted then
    begin
      TFile.Copy(Source, Target);
    end;
  end;
end;

procedure TFireDACStoreContractTests.InsertUserWithAccount(const UserId, ObjectId, LinkedAt: string);
begin
  TTestPostgres.Execute(FFactory, Format(InsertTestUser, [UserId, LinkedAt]));
  InsertAccount(UserId, ObjectId, LinkedAt);
end;

procedure TFireDACStoreContractTests.InsertAccount(const UserId, ObjectId, LinkedAt: string);
begin
  TTestPostgres.Execute(FFactory, Format(InsertTestAccount, [ObjectId, UserId, LinkedAt]));
end;

function TFireDACStoreContractTests.IdentityKeyOf(const UserId: string): string;
begin
  const Connection = FFactory.NewConnection;
  try
    Result := Connection.ExecSQLScalar(Format('SELECT identity_key FROM mcpauth_login_identities WHERE user_id = ''%s''', [UserId]));
  finally
    Connection.Free;
  end;
end;

end.
