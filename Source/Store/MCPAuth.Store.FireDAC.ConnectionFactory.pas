unit MCPAuth.Store.FireDAC.ConnectionFactory;

interface

uses
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

  public
    constructor Create(const ConnectionString: string);
    destructor Destroy; override;

    function NewConnection: TFDConnection;
  end;

implementation

uses
  System.SysUtils,
  System.Classes,
  FireDAC.Stan.Def,
  FireDAC.Stan.Async,
  FireDAC.Stan.Pool,
  FireDAC.DApt,
  MCPAuth.Store.FireDAC.Exceptions;

const
  DriverIdParam = 'DriverID';
  PooledParam = 'Pooled';
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
    FDManager.AddConnectionDef(FDefinitionName, DriverId, Params);
  finally
    Params.Free;
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
