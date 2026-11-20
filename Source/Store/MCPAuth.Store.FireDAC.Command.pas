unit MCPAuth.Store.FireDAC.Command;

interface

uses
  System.SysUtils,
  FireDAC.Comp.Client,
  MCPAuth.Store.FireDAC.Interfaces;

type
  // One SQL statement on a connection of its own from the factory; the connection goes back to the pool on free.
  // Times are passed and read as UTC with an explicit offset, so neither the session nor the machine time zone shifts them.
  TFireDACCommand = class
  private
    FConnection: TFDConnection;
    FQuery: TFDQuery;

  public
    class function IsUniqueViolation(const Error: Exception): Boolean; static;

    constructor Create(const Factory: IFireDACConnectionFactory; const Sql: string);
    destructor Destroy; override;

    procedure SetText(const Name, Value: string);
    procedure SetLongText(const Name, Value: string);
    procedure SetUtc(const Name: string; const Value: TDateTime);
    procedure SetFlag(const Name: string; const Value: Boolean);
    procedure SetBytes(const Name: string; const Value: TBytes);

    // Returns the number of affected rows.
    function Execute: Integer;
    procedure Open;
    function Eof: Boolean;
    procedure Next;

    function Text(const Field: string): string;
    function Utc(const Field: string): TDateTime;
    function Flag(const Field: string): Boolean;
    function Bytes(const Field: string): TBytes;
    function Int(const Field: string): Int64;
  end;

implementation

uses
  System.Classes,
  Data.DB,
  Data.SqlTimSt,
  FireDAC.Stan.Param,
  FireDAC.Stan.Error;

{ TFireDACCommand }

class function TFireDACCommand.IsUniqueViolation(const Error: Exception): Boolean;
begin
  Result := ((Error is EFDDBEngineException) and (EFDDBEngineException(Error).Kind = TFDCommandExceptionKind.ekUKViolated));
end;

constructor TFireDACCommand.Create(const Factory: IFireDACConnectionFactory; const Sql: string);
begin
  inherited Create;

  FConnection := Factory.NewConnection;
  FQuery := TFDQuery.Create(nil);
  FQuery.Connection := FConnection;
  FQuery.SQL.Text := Sql;
end;

destructor TFireDACCommand.Destroy;
begin
  FQuery.Free;
  FConnection.Free;
  inherited Destroy;
end;

procedure TFireDACCommand.SetText(const Name, Value: string);
begin
  // On Linux an AsString parameter reaches libpq as UTF-16, which PostgreSQL rejects for non-ASCII text.
  const Param = FQuery.ParamByName(Name);
  Param.DataType := ftWideString;
  Param.AsWideString := Value;
end;

procedure TFireDACCommand.SetLongText(const Name, Value: string);
begin
  FQuery.ParamByName(Name).AsWideMemo := Value;
end;

procedure TFireDACCommand.SetUtc(const Name: string; const Value: TDateTime);
begin
  FQuery.ParamByName(Name).AsSQLTimeStampOffset := DateTimeToSQLTimeStampOffset(Value, 0, 0);
end;

procedure TFireDACCommand.SetFlag(const Name: string; const Value: Boolean);
begin
  FQuery.ParamByName(Name).AsBoolean := Value;
end;

procedure TFireDACCommand.SetBytes(const Name: string; const Value: TBytes);
begin
  const Stream = TBytesStream.Create(Value);
  try
    FQuery.ParamByName(Name).LoadFromStream(Stream, ftBlob);
  finally
    Stream.Free;
  end;
end;

function TFireDACCommand.Execute: Integer;
begin
  FQuery.ExecSQL;
  Result := FQuery.RowsAffected;
end;

procedure TFireDACCommand.Open;
begin
  FQuery.Open;
end;

function TFireDACCommand.Eof: Boolean;
begin
  Result := FQuery.Eof;
end;

procedure TFireDACCommand.Next;
begin
  FQuery.Next;
end;

function TFireDACCommand.Text(const Field: string): string;
begin
  Result := FQuery.FieldByName(Field).AsString;
end;

function TFireDACCommand.Utc(const Field: string): TDateTime;
begin
  // AsDateTime of an offset field converts to the local time of this machine; OffsetToUTC does not.
  const Stamp = FQuery.FieldByName(Field).AsSQLTimeStampOffset;
  Result := SQLTimeStampToDateTime(OffsetToUTC(Stamp));
end;

function TFireDACCommand.Flag(const Field: string): Boolean;
begin
  Result := FQuery.FieldByName(Field).AsBoolean;
end;

function TFireDACCommand.Bytes(const Field: string): TBytes;
begin
  Result := FQuery.FieldByName(Field).AsBytes;
end;

function TFireDACCommand.Int(const Field: string): Int64;
begin
  Result := FQuery.FieldByName(Field).AsLargeInt;
end;

end.
