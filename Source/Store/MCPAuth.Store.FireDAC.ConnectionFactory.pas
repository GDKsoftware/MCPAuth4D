unit MCPAuth.Store.FireDAC.ConnectionFactory;

interface

uses
  System.Classes,
  FireDAC.Comp.Client,
  MCPAuth.Store.FireDAC.Interfaces;

type
  // Registers a private, pooled FireDAC connection definition from a connection string such as
  // 'DriverID=PG;Server=127.0.0.1;Port=5432;Database=mcpauth;User_Name=mcpauth;Password=...'.
  // The driver itself must be linked into the program, for example through TFireDACPgDriver.
  TFireDACConnectionFactory = class(TInterfacedObject, IFireDACConnectionFactory)
  private
    FDefinitionName: string;

    procedure GuardConnectionString(const ConnectionString: string);
    procedure RegisterDefinition(const ConnectionString: string);
    procedure DefaultToUtf8(const DriverId: string; const Params: TStrings);

  public
    constructor Create(const ConnectionString: string);
    destructor Destroy; override;

    function NewConnection: TFDConnection;
  end;

implementation

uses
  System.SysUtils,
  FireDAC.Stan.Def,
  FireDAC.Stan.Async,
  FireDAC.Stan.Pool,
  FireDAC.DApt,
  MCPAuth.Store.FireDAC.Exceptions;

const
  DriverIdParam = 'DriverID';
  PooledParam = 'Pooled';
  PostgresDriverId = 'PG';
  CharacterSetParam = 'CharacterSet';
  Utf8CharacterSet = 'UTF8';
  ParamSeparator = ';';

{ TFireDACConnectionFactory }

constructor TFireDACConnectionFactory.Create(const ConnectionString: string);
begin
  inherited Create;

  GuardConnectionString(ConnectionString);
  FDefinitionName := 'MCPAuth.' + TGUID.NewGuid.ToString;
  RegisterDefinition(ConnectionString);
end;

destructor TFireDACConnectionFactory.Destroy;
begin
  const IsRegistered = (not FDefinitionName.IsEmpty and FDManager.IsConnectionDef(FDefinitionName));
  if IsRegistered then
  begin
    FDManager.CloseConnectionDef(FDefinitionName);
    FDManager.DeleteConnectionDef(FDefinitionName);
  end;

  inherited Destroy;
end;

procedure TFireDACConnectionFactory.GuardConnectionString(const ConnectionString: string);
begin
  const IsMissing = ConnectionString.Trim.IsEmpty;
  if IsMissing then
  begin
    raise EFireDACStoreError.Create('The connection string is empty');
  end;
end;

procedure TFireDACConnectionFactory.RegisterDefinition(const ConnectionString: string);
begin
  const Params = TStringList.Create;
  try
    Params.Delimiter := ParamSeparator;
    Params.StrictDelimiter := True;
    Params.DelimitedText := ConnectionString;

    const DriverId = Params.Values[DriverIdParam];
    if DriverId.IsEmpty then
    begin
      raise EFireDACStoreError.CreateFmt('The connection string has no %s', [DriverIdParam]);
    end;

    Params.Values[DriverIdParam] := '';
    Params.Values[PooledParam] := BoolToStr(True, True);
    DefaultToUtf8(DriverId, Params);
    FDManager.AddConnectionDef(FDefinitionName, DriverId, Params);
  finally
    Params.Free;
  end;
end;

// Names and other text from real users are not ASCII; the client encoding must not depend on the server or locale defaults.
procedure TFireDACConnectionFactory.DefaultToUtf8(const DriverId: string; const Params: TStrings);
begin
  const IsPostgres = SameText(DriverId, PostgresDriverId);
  const HasOwnCharacterSet = not Params.Values[CharacterSetParam].IsEmpty;
  if (IsPostgres and not HasOwnCharacterSet) then
  begin
    Params.Values[CharacterSetParam] := Utf8CharacterSet;
  end;
end;

function TFireDACConnectionFactory.NewConnection: TFDConnection;
begin
  Result := TFDConnection.Create(nil);
  try
    Result.ConnectionDefName := FDefinitionName;
    Result.ResourceOptions.SilentMode := True;
    Result.LoginPrompt := False;
    Result.Open;
  except
    Result.Free;
    raise;
  end;
end;

end.
