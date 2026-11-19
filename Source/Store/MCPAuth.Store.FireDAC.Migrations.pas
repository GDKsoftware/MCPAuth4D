unit MCPAuth.Store.FireDAC.Migrations;

interface

uses
  Spring.Collections,
  FireDAC.Comp.Client,
  MCPAuth.Store.FireDAC.Interfaces,
  MCPAuth.Store.FireDAC.Dialect;

type
  TMigrationFile = record
    Version: Integer;
    Name: string;
    Path: string;
  end;

  // Runs <MigrationsPath>/<dialect>/NNNN_*.sql in order of NNNN, each file in a transaction of its own together with
  // its row in the version table. Applied versions are skipped, so a rerun changes nothing. The version table is
  // locked per file, so servers that start at the same time apply each file once.
  TFireDACMigrations = class
  private
    class procedure GuardVersionTable(const VersionTable: string); static;
    class function FindFiles(const Folder: string): IReadOnlyList<TMigrationFile>; static;
    class function TryParseVersion(const FileName: string; out Version: Integer): Boolean; static;
    class procedure ApplyFile(const Connection: TFDConnection; const Dialect: TSqlDialect; const VersionTable: string; const MigrationFile: TMigrationFile); static;
    class function IsApplied(const Connection: TFDConnection; const VersionTable: string; const Version: Integer): Boolean; static;
    class procedure RunScript(const Connection: TFDConnection; const Script: string); static;
    class procedure RecordVersion(const Connection: TFDConnection; const VersionTable: string; const MigrationFile: TMigrationFile); static;

  public
    class procedure Apply(const Factory: IFireDACConnectionFactory; const Dialect, MigrationsPath: string; const VersionTable: string = 'mcpauth_schema_version'); static;
  end;

implementation

uses
  System.SysUtils,
  System.IOUtils,
  System.RegularExpressions,
  MCPAuth.Store.FireDAC.Exceptions;

const
  VersionTablePattern = '^[a-z_][a-z0-9_]{0,62}$';
  MigrationFilePattern = '^([0-9]{4})_[A-Za-z0-9_.-]+\.sql$';
  MigrationFileMask = '*.sql';

{ TFireDACMigrations }

class procedure TFireDACMigrations.Apply(const Factory: IFireDACConnectionFactory; const Dialect, MigrationsPath: string; const VersionTable: string);
begin
  GuardVersionTable(VersionTable);
  const SqlDialect = TSqlDialect.ForName(Dialect);
  const Files = FindFiles(TPath.Combine(MigrationsPath, SqlDialect.Name));

  const Connection = Factory.NewConnection;
  try
    Connection.ExecSQL(SqlDialect.CreateVersionTable(VersionTable));

    for var MigrationFile in Files do
    begin
      ApplyFile(Connection, SqlDialect, VersionTable, MigrationFile);
    end;
  finally
    Connection.Free;
  end;
end;

class procedure TFireDACMigrations.GuardVersionTable(const VersionTable: string);
begin
  const IsValidName = TRegEx.IsMatch(VersionTable, VersionTablePattern);
  if not IsValidName then
  begin
    raise EMigrationError.CreateFmt('Invalid version table name "%s"; use lowercase letters, digits and underscores', [VersionTable]);
  end;
end;

class function TFireDACMigrations.FindFiles(const Folder: string): IReadOnlyList<TMigrationFile>;
begin
  const IsFolderPresent = TDirectory.Exists(Folder);
  if not IsFolderPresent then
  begin
    raise EMigrationError.CreateFmt('Migrations folder not found: %s', [Folder]);
  end;

  const Files = TCollections.CreateList<TMigrationFile>;
  const Versions = TCollections.CreateSet<Integer>;
  for var Path in TDirectory.GetFiles(Folder, MigrationFileMask) do
  begin
    var MigrationFile: TMigrationFile;
    MigrationFile.Name := TPath.GetFileName(Path);
    MigrationFile.Path := Path;
    if not TryParseVersion(MigrationFile.Name, MigrationFile.Version) then
    begin
      Continue;
    end;

    const IsDuplicate = not Versions.Add(MigrationFile.Version);
    if IsDuplicate then
    begin
      raise EMigrationError.CreateFmt('Two migrations have version %d in %s', [MigrationFile.Version, Folder]);
    end;
    Files.Add(MigrationFile);
  end;

  Files.Sort(
    function(const Left, Right: TMigrationFile): Integer
    begin
      Result := Left.Version - Right.Version;
    end);
  Result := Files.AsReadOnly;
end;

class function TFireDACMigrations.TryParseVersion(const FileName: string; out Version: Integer): Boolean;
begin
  Version := 0;

  const Match = TRegEx.Match(FileName, MigrationFilePattern);
  Result := Match.Success;
  if Result then
  begin
    Version := Match.Groups[1].Value.ToInteger;
  end;
end;

class procedure TFireDACMigrations.ApplyFile(const Connection: TFDConnection; const Dialect: TSqlDialect; const VersionTable: string; const MigrationFile: TMigrationFile);
begin
  Connection.StartTransaction;
  try
    Connection.ExecSQL(Dialect.LockVersionTable(VersionTable));
    if not IsApplied(Connection, VersionTable, MigrationFile.Version) then
    begin
      RunScript(Connection, TFile.ReadAllText(MigrationFile.Path, TEncoding.UTF8));
      RecordVersion(Connection, VersionTable, MigrationFile);
    end;
    Connection.Commit;
  except
    on Error: Exception do
    begin
      Connection.Rollback;
      raise EMigrationError.CreateFmt('Migration %s failed: %s', [MigrationFile.Name, Error.Message]);
    end;
  end;
end;

class function TFireDACMigrations.IsApplied(const Connection: TFDConnection; const VersionTable: string; const Version: Integer): Boolean;
begin
  const Sql = Format('SELECT COUNT(*) FROM %s WHERE version = :version', [VersionTable]);
  Result := (Connection.ExecSQLScalar(Sql, [Version]) > 0);
end;

class procedure TFireDACMigrations.RunScript(const Connection: TFDConnection; const Script: string);
begin
  // Sent as one batch without preparing it, so a file may hold several statements and ':' needs no escaping.
  const Query = TFDQuery.Create(nil);
  try
    Query.Connection := Connection;
    Query.ResourceOptions.DirectExecute := True;
    Query.ResourceOptions.ParamCreate := False;
    Query.ResourceOptions.MacroCreate := False;
    Query.ResourceOptions.MacroExpand := False;
    Query.ResourceOptions.EscapeExpand := False;
    Query.SQL.Text := Script;
    Query.ExecSQL;
  finally
    Query.Free;
  end;
end;

class procedure TFireDACMigrations.RecordVersion(const Connection: TFDConnection; const VersionTable: string; const MigrationFile: TMigrationFile);
begin
  const Sql = Format('INSERT INTO %s (version, name, applied_at) VALUES (:version, :name, CURRENT_TIMESTAMP)', [VersionTable]);
  Connection.ExecSQL(Sql, [MigrationFile.Version, MigrationFile.Name]);
end;

end.
