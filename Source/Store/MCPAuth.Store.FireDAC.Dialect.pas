unit MCPAuth.Store.FireDAC.Dialect;

interface

type
  // All database-specific SQL of the FireDAC store. The repositories use plain SQL for everything else.
  TSqlDialect = record
    Name: string;                        // folder name of the migrations, for example 'postgres'
    UpsertFormat: string;                // %0:s table, %1:s columns, %2:s values, %3:s key column, %4:s assignments
    ReturningFormat: string;             // %0:s statement, %1:s returned columns
    ExcludedColumnFormat: string;        // %0:s column; the new value inside an upsert assignment
    CreateVersionTableFormat: string;    // %0:s version table
    LockVersionTableFormat: string;      // %0:s version table

    class function Postgres: TSqlDialect; static;
    class function ForName(const Name: string): TSqlDialect; static;

    // Inserts the row or, when KeyColumn already exists, updates the other columns.
    function Upsert(const Table, KeyColumn: string; const Columns: TArray<string>): string;
    function Returning(const Statement: string; const Columns: TArray<string>): string;
    function CreateVersionTable(const VersionTable: string): string;
    function LockVersionTable(const VersionTable: string): string;
  end;

implementation

uses
  System.SysUtils,
  MCPAuth.Store.FireDAC.Exceptions;

const
  ColumnSeparator = ', ';

{ TSqlDialect }

class function TSqlDialect.Postgres: TSqlDialect;
begin
  Result.Name                     := 'postgres';
  Result.UpsertFormat             := 'INSERT INTO %0:s (%1:s) VALUES (%2:s) ON CONFLICT (%3:s) DO UPDATE SET %4:s';
  Result.ReturningFormat          := '%0:s RETURNING %1:s';
  Result.ExcludedColumnFormat     := 'EXCLUDED.%0:s';
  Result.CreateVersionTableFormat := 'CREATE TABLE IF NOT EXISTS %0:s (version integer PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL)';
  Result.LockVersionTableFormat   := 'LOCK TABLE %0:s IN EXCLUSIVE MODE';
end;

class function TSqlDialect.ForName(const Name: string): TSqlDialect;
begin
  const IsPostgres = SameText(Name, Postgres.Name);
  if not IsPostgres then
  begin
    raise EFireDACStoreError.CreateFmt('Unknown SQL dialect "%s"', [Name]);
  end;

  Result := Postgres;
end;

function TSqlDialect.Upsert(const Table, KeyColumn: string; const Columns: TArray<string>): string;
begin
  var Parameters: TArray<string>;
  var Assignments: TArray<string>;
  for var Column in Columns do
  begin
    Parameters := Parameters + [':' + Column];

    const IsKeyColumn = SameText(Column, KeyColumn);
    if not IsKeyColumn then
    begin
      Assignments := Assignments + [Format('%s = %s', [Column, Format(ExcludedColumnFormat, [Column])])];
    end;
  end;

  Result := Format(UpsertFormat, [Table,
                                  string.Join(ColumnSeparator, Columns),
                                  string.Join(ColumnSeparator, Parameters),
                                  KeyColumn,
                                  string.Join(ColumnSeparator, Assignments)]);
end;

function TSqlDialect.Returning(const Statement: string; const Columns: TArray<string>): string;
begin
  Result := Format(ReturningFormat, [Statement, string.Join(ColumnSeparator, Columns)]);
end;

function TSqlDialect.CreateVersionTable(const VersionTable: string): string;
begin
  Result := Format(CreateVersionTableFormat, [VersionTable]);
end;

function TSqlDialect.LockVersionTable(const VersionTable: string): string;
begin
  Result := Format(LockVersionTableFormat, [VersionTable]);
end;

end.
