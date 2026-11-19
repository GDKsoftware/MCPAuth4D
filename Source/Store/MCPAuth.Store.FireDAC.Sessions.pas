unit MCPAuth.Store.FireDAC.Sessions;

interface

uses
  MCPAuth.Clock.Interfaces,
  MCPAuth.Web.Types,
  MCPAuth.Store.Interfaces,
  MCPAuth.Store.FireDAC.Interfaces,
  MCPAuth.Store.FireDAC.Dialect;

type
  TFireDACSessionStore = class(TInterfacedObject, ISessionStore)
  private
    FFactory: IFireDACConnectionFactory;
    FDialect: TSqlDialect;
    FClock: IClock;

  public
    constructor Create(const Factory: IFireDACConnectionFactory; const Dialect: TSqlDialect; const Clock: IClock);

    procedure Put(const Session: TWebSession);
    function TryGet(const IdHash: string; out Session: TWebSession): Boolean;
    procedure Remove(const IdHash: string);
    function DeleteExpired(const NowUtc: TDateTime): Integer;
  end;

implementation

uses
  MCPAuth.Store.FireDAC.Command;

const
  SelectSession = 'SELECT id_hash, user_id, csrf_token, expires_at FROM mcpauth_sessions WHERE id_hash = :id_hash AND expires_at > :now';
  DeleteSession = 'DELETE FROM mcpauth_sessions WHERE id_hash = :id_hash';
  DeleteExpiredSessions = 'DELETE FROM mcpauth_sessions WHERE expires_at <= :now';

{ TFireDACSessionStore }

constructor TFireDACSessionStore.Create(const Factory: IFireDACConnectionFactory; const Dialect: TSqlDialect; const Clock: IClock);
begin
  inherited Create;
  FFactory := Factory;
  FDialect := Dialect;
  FClock := Clock;
end;

procedure TFireDACSessionStore.Put(const Session: TWebSession);
begin
  const Sql = FDialect.Upsert('mcpauth_sessions', 'id_hash', ['id_hash', 'user_id', 'csrf_token', 'expires_at']);
  const Command = TFireDACCommand.Create(FFactory, Sql);
  try
    Command.SetText('id_hash', Session.IdHash);
    Command.SetText('user_id', Session.UserId);
    Command.SetText('csrf_token', Session.CsrfToken);
    Command.SetUtc('expires_at', Session.ExpiresAtUtc);
    Command.Execute;
  finally
    Command.Free;
  end;
end;

function TFireDACSessionStore.TryGet(const IdHash: string; out Session: TWebSession): Boolean;
begin
  Session := Default(TWebSession);

  const Command = TFireDACCommand.Create(FFactory, SelectSession);
  try
    Command.SetText('id_hash', IdHash);
    Command.SetUtc('now', FClock.NowUtc);
    Command.Open;

    Result := not Command.Eof;
    if Result then
    begin
      Session.IdHash := Command.Text('id_hash');
      Session.UserId := Command.Text('user_id');
      Session.CsrfToken := Command.Text('csrf_token');
      Session.ExpiresAtUtc := Command.Utc('expires_at');
    end;
  finally
    Command.Free;
  end;
end;

procedure TFireDACSessionStore.Remove(const IdHash: string);
begin
  const Command = TFireDACCommand.Create(FFactory, DeleteSession);
  try
    Command.SetText('id_hash', IdHash);
    Command.Execute;
  finally
    Command.Free;
  end;
end;

function TFireDACSessionStore.DeleteExpired(const NowUtc: TDateTime): Integer;
begin
  const Command = TFireDACCommand.Create(FFactory, DeleteExpiredSessions);
  try
    Command.SetUtc('now', NowUtc);
    Result := Command.Execute;
  finally
    Command.Free;
  end;
end;

end.
