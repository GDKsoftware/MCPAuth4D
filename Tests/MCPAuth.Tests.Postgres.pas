unit MCPAuth.Tests.Postgres;

interface

uses
  MCPAuth.Store.FireDAC.Interfaces;

type
  // Access to the test database named by MCPAUTH_TEST_PG, a FireDAC connection string such as
  // 'DriverID=PG;Server=127.0.0.1;Port=55432;Database=mcpauth_test;User_Name=mcpauth_test;Password=mcpauth_test'.
  // MCPAUTH_PG_VENDORLIB optionally names the libpq library to load.
  TTestPostgres = class
  public
    class function UnavailableReason: string; static;
    class function ConnectionString: string; static;
    class function VendorLib: string; static;
    class function MigrationsPath: string; static;
    class procedure Execute(const Factory: IFireDACConnectionFactory; const Sql: string); static;
    class function QueryInt(const Factory: IFireDACConnectionFactory; const Sql: string): Int64; static;
  end;

implementation

uses
  System.SysUtils,
  System.IOUtils;

const
  ConnectionStringVariable = 'MCPAUTH_TEST_PG';
  VendorLibVariable = 'MCPAUTH_PG_VENDORLIB';
  MigrationsFolder = 'migrations';

{ TTestPostgres }

class function TTestPostgres.UnavailableReason: string;
begin
  if ConnectionString.IsEmpty then
  begin
    Result := Format('%s not set', [ConnectionStringVariable]);
  end
  else
  begin
    Result := '';
  end;
end;

class function TTestPostgres.ConnectionString: string;
begin
  Result := GetEnvironmentVariable(ConnectionStringVariable).Trim;
end;

class function TTestPostgres.VendorLib: string;
begin
  Result := GetEnvironmentVariable(VendorLibVariable).Trim;
end;

class function TTestPostgres.MigrationsPath: string;
begin
  var Folder := TPath.GetDirectoryName(ParamStr(0));
  while not Folder.IsEmpty do
  begin
    const Candidate = TPath.Combine(Folder, MigrationsFolder);
    if TDirectory.Exists(Candidate) then
    begin
      Exit(Candidate);
    end;

    const Parent = TPath.GetDirectoryName(Folder);
    if Parent = Folder then
    begin
      Break;
    end;
    Folder := Parent;
  end;

  raise Exception.CreateFmt('Folder "%s" not found above %s', [MigrationsFolder, ParamStr(0)]);
end;

class procedure TTestPostgres.Execute(const Factory: IFireDACConnectionFactory; const Sql: string);
begin
  const Connection = Factory.NewConnection;
  try
    Connection.ExecSQL(Sql);
  finally
    Connection.Free;
  end;
end;

class function TTestPostgres.QueryInt(const Factory: IFireDACConnectionFactory; const Sql: string): Int64;
begin
  const Connection = Factory.NewConnection;
  try
    Result := Connection.ExecSQLScalar(Sql);
  finally
    Connection.Free;
  end;
end;

end.
