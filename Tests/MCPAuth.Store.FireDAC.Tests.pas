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
  end;

implementation

uses
  System.SysUtils,
  System.DateUtils,
  MCPAuth.Fakes.Clock,
  MCPAuth.OAuth.Types,
  MCPAuth.Store.FireDAC,
  MCPAuth.Store.FireDAC.ConnectionFactory,
  MCPAuth.Store.FireDAC.Migrations,
  MCPAuth.Tests.Postgres;

const
  StoreTables: array[0..6] of string = ('mcpauth_users', 'mcpauth_linked_accounts', 'mcpauth_clients', 'mcpauth_pending_authorizations',
                                        'mcpauth_grants', 'mcpauth_tokens', 'mcpauth_sessions');
  VersionTable = 'mcpauth_schema_version';
  UtcTokenHash = 'utc-token';
  // 2026-06-01 12:00:00 UTC
  UtcExpiryUnix = 1780315200;

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
  for var Table in StoreTables do
  begin
    TTestPostgres.Execute(FFactory, Format('DROP TABLE IF EXISTS %s', [Table]));
  end;
  TTestPostgres.Execute(FFactory, Format('DROP TABLE IF EXISTS %s', [VersionTable]));
  TFireDACMigrations.Apply(FFactory, 'postgres', TTestPostgres.MigrationsPath);
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

end.
