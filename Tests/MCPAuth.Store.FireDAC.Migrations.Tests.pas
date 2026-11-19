unit MCPAuth.Store.FireDAC.Migrations.Tests;

interface

uses
  DUnitX.TestFramework,
  MCPAuth.Store.FireDAC.Interfaces,
  MCPAuth.Store.FireDAC.PgDriver;

type
  // Tests that need a database pass without one when MCPAUTH_TEST_PG is not set.
  [TestFixture]
  TFireDACMigrationsTests = class
  private
    FDriver: TFireDACPgDriver;
    FFactory: IFireDACConnectionFactory;
    FMigrationsPath: string;

    procedure RequireDatabase;
    procedure DropTestTables;
    procedure WriteMigration(const FileName, Sql: string);
    procedure Apply;
    function TableExists(const Table: string): Boolean;

  public
    [SetupFixture]
    procedure SetupFixture;

    [TearDownFixture]
    procedure TearDownFixture;

    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure AppliesFilesInOrderAndRecordsTheirVersions;

    [Test]
    procedure RerunAppliesNothingTwice;

    [Test]
    procedure LaterFileIsAppliedOnNextRun;

    [Test]
    procedure FailingFileIsRolledBackAndNotRecorded;

    [Test]
    procedure InvalidVersionTableIsRejected;

    [Test]
    procedure UnknownDialectIsRejected;
  end;

implementation

uses
  System.SysUtils,
  System.IOUtils,
  MCPAuth.Store.FireDAC.ConnectionFactory,
  MCPAuth.Store.FireDAC.Exceptions,
  MCPAuth.Store.FireDAC.Migrations,
  MCPAuth.Tests.Postgres;

const
  Dialect = 'postgres';
  VersionTable = 'mcpauth_test_migrations';
  FirstTable = 'mcpauth_test_first';
  SecondTable = 'mcpauth_test_second';

{ TFireDACMigrationsTests }

procedure TFireDACMigrationsTests.SetupFixture;
begin
  const IsAvailable = TTestPostgres.UnavailableReason.IsEmpty;
  if IsAvailable then
  begin
    FDriver := TFireDACPgDriver.Create(TTestPostgres.VendorLib);
    FFactory := TFireDACConnectionFactory.Create(TTestPostgres.ConnectionString);
  end;
end;

procedure TFireDACMigrationsTests.TearDownFixture;
begin
  FFactory := nil;
  FreeAndNil(FDriver);
end;

procedure TFireDACMigrationsTests.Setup;
begin
  FMigrationsPath := TPath.Combine(TPath.GetTempPath, 'mcpauth-migrations-' + TGUID.NewGuid.ToString);
  TDirectory.CreateDirectory(TPath.Combine(FMigrationsPath, Dialect));
  if Assigned(FFactory) then
  begin
    DropTestTables;
  end;
end;

procedure TFireDACMigrationsTests.TearDown;
begin
  TDirectory.Delete(FMigrationsPath, True);
  if Assigned(FFactory) then
  begin
    DropTestTables;
  end;
end;

procedure TFireDACMigrationsTests.RequireDatabase;
begin
  const Reason = TTestPostgres.UnavailableReason;
  if not Reason.IsEmpty then
  begin
    Assert.Pass(Reason);
  end;
end;

procedure TFireDACMigrationsTests.DropTestTables;
begin
  for var Table in [VersionTable, FirstTable, SecondTable] do
  begin
    TTestPostgres.Execute(FFactory, Format('DROP TABLE IF EXISTS %s', [Table]));
  end;
end;

procedure TFireDACMigrationsTests.WriteMigration(const FileName, Sql: string);
begin
  TFile.WriteAllText(TPath.Combine(TPath.Combine(FMigrationsPath, Dialect), FileName), Sql, TEncoding.UTF8);
end;

procedure TFireDACMigrationsTests.Apply;
begin
  TFireDACMigrations.Apply(FFactory, Dialect, FMigrationsPath, VersionTable);
end;

function TFireDACMigrationsTests.TableExists(const Table: string): Boolean;
begin
  const Sql = Format('SELECT CASE WHEN to_regclass(''%s'') IS NULL THEN 0 ELSE 1 END', [Table]);
  Result := (TTestPostgres.QueryInt(FFactory, Sql) = 1);
end;

procedure TFireDACMigrationsTests.AppliesFilesInOrderAndRecordsTheirVersions;
begin
  RequireDatabase;
  WriteMigration('0002_fill.sql', Format('INSERT INTO %s (id, note) VALUES (1, ''a:b'');', [FirstTable]));
  WriteMigration('0001_create.sql', Format('CREATE TABLE %0:s (id integer PRIMARY KEY, note text);'#10'CREATE INDEX %0:s_note ON %0:s (note);', [FirstTable]));
  WriteMigration('readme.txt', 'not a migration');

  Apply;

  Assert.AreEqual<Int64>(1, TTestPostgres.QueryInt(FFactory, Format('SELECT COUNT(*) FROM %s', [FirstTable])));
  Assert.AreEqual<Int64>(2, TTestPostgres.QueryInt(FFactory, Format('SELECT COUNT(*) FROM %s', [VersionTable])));
  Assert.AreEqual<Int64>(2, TTestPostgres.QueryInt(FFactory, Format('SELECT MAX(version) FROM %s', [VersionTable])));
end;

procedure TFireDACMigrationsTests.RerunAppliesNothingTwice;
begin
  RequireDatabase;
  WriteMigration('0001_create.sql', Format('CREATE TABLE %s (id integer PRIMARY KEY);', [FirstTable]));
  WriteMigration('0002_fill.sql', Format('INSERT INTO %s (id) VALUES (1);', [FirstTable]));

  Apply;
  Apply;

  Assert.AreEqual<Int64>(1, TTestPostgres.QueryInt(FFactory, Format('SELECT COUNT(*) FROM %s', [FirstTable])));
  Assert.AreEqual<Int64>(2, TTestPostgres.QueryInt(FFactory, Format('SELECT COUNT(*) FROM %s', [VersionTable])));
end;

procedure TFireDACMigrationsTests.LaterFileIsAppliedOnNextRun;
begin
  RequireDatabase;
  WriteMigration('0001_create.sql', Format('CREATE TABLE %s (id integer PRIMARY KEY);', [FirstTable]));
  Apply;
  WriteMigration('0002_second.sql', Format('CREATE TABLE %s (id integer PRIMARY KEY);', [SecondTable]));

  Apply;

  Assert.IsTrue(TableExists(SecondTable));
  Assert.AreEqual<Int64>(2, TTestPostgres.QueryInt(FFactory, Format('SELECT COUNT(*) FROM %s', [VersionTable])));
end;

procedure TFireDACMigrationsTests.FailingFileIsRolledBackAndNotRecorded;
begin
  RequireDatabase;
  WriteMigration('0001_create.sql', Format('CREATE TABLE %s (id integer PRIMARY KEY);', [FirstTable]));
  WriteMigration('0002_broken.sql', Format('CREATE TABLE %s (id integer PRIMARY KEY);'#10'SELECT * FROM mcpauth_test_missing;', [SecondTable]));

  Assert.WillRaise(Apply, EMigrationError);

  Assert.IsTrue(TableExists(FirstTable));
  Assert.IsFalse(TableExists(SecondTable));
  Assert.AreEqual<Int64>(1, TTestPostgres.QueryInt(FFactory, Format('SELECT COUNT(*) FROM %s', [VersionTable])));
end;

procedure TFireDACMigrationsTests.InvalidVersionTableIsRejected;
begin
  Assert.WillRaise(
    procedure
    begin
      TFireDACMigrations.Apply(nil, Dialect, FMigrationsPath, 'versions; DROP TABLE x');
    end,
    EMigrationError);
end;

procedure TFireDACMigrationsTests.UnknownDialectIsRejected;
begin
  Assert.WillRaise(
    procedure
    begin
      TFireDACMigrations.Apply(nil, 'unknown', FMigrationsPath);
    end,
    EFireDACStoreError);
end;

end.
