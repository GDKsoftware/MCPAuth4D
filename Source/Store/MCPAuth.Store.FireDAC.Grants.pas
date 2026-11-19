unit MCPAuth.Store.FireDAC.Grants;

interface

uses
  MCPAuth.Clock.Interfaces,
  MCPAuth.OAuth.Types,
  MCPAuth.OAuth.Interfaces,
  MCPAuth.Store.FireDAC.Interfaces,
  MCPAuth.Store.FireDAC.Dialect;

type
  TFireDACGrantStore = class(TInterfacedObject, IGrantStore)
  private
    FFactory: IFireDACConnectionFactory;
    FDialect: TSqlDialect;
    FClock: IClock;

  public
    constructor Create(const Factory: IFireDACConnectionFactory; const Dialect: TSqlDialect; const Clock: IClock);

    procedure Put(const Grant: TAuthorizationGrant);
    function TryTake(const CodeHash: string; out Grant: TAuthorizationGrant): Boolean;
  end;

implementation

uses
  System.SysUtils,
  MCPAuth.Store.FireDAC.Command;

const
  Table = 'mcpauth_grants';
  Columns: TArray<string> = ['code_hash', 'client_id', 'redirect_uri', 'code_challenge', 'user_id', 'scope', 'resource', 'expires_at'];

{ TFireDACGrantStore }

constructor TFireDACGrantStore.Create(const Factory: IFireDACConnectionFactory; const Dialect: TSqlDialect; const Clock: IClock);
begin
  inherited Create;
  FFactory := Factory;
  FDialect := Dialect;
  FClock := Clock;
end;

procedure TFireDACGrantStore.Put(const Grant: TAuthorizationGrant);
begin
  const Command = TFireDACCommand.Create(FFactory, FDialect.Upsert(Table, 'code_hash', Columns));
  try
    Command.SetText('code_hash', Grant.CodeHash);
    Command.SetText('client_id', Grant.ClientId);
    Command.SetText('redirect_uri', Grant.RedirectUri);
    Command.SetText('code_challenge', Grant.CodeChallenge);
    Command.SetText('user_id', Grant.UserId);
    Command.SetText('scope', Grant.Scope);
    Command.SetText('resource', Grant.Resource);
    Command.SetUtc('expires_at', Grant.ExpiresAtUtc);
    Command.Execute;
  finally
    Command.Free;
  end;
end;

function TFireDACGrantStore.TryTake(const CodeHash: string; out Grant: TAuthorizationGrant): Boolean;
begin
  Grant := Default(TAuthorizationGrant);

  // An expired grant is removed as well, but counts as absent.
  const Sql = FDialect.Returning(Format('DELETE FROM %s WHERE code_hash = :code_hash', [Table]), Columns);
  const Command = TFireDACCommand.Create(FFactory, Sql);
  try
    Command.SetText('code_hash', CodeHash);
    Command.Open;

    const IsFound = not Command.Eof;
    if IsFound then
    begin
      Grant.CodeHash := Command.Text('code_hash');
      Grant.ClientId := Command.Text('client_id');
      Grant.RedirectUri := Command.Text('redirect_uri');
      Grant.CodeChallenge := Command.Text('code_challenge');
      Grant.UserId := Command.Text('user_id');
      Grant.Scope := Command.Text('scope');
      Grant.Resource := Command.Text('resource');
      Grant.ExpiresAtUtc := Command.Utc('expires_at');
    end;
    Result := (IsFound and (Grant.ExpiresAtUtc > FClock.NowUtc));
  finally
    Command.Free;
  end;
end;

end.
