unit MCPAuth.Store.FireDAC.Users;

interface

uses
  MCPAuth.Identity.Types,
  MCPAuth.Identity.Interfaces,
  MCPAuth.Store.FireDAC.Interfaces,
  MCPAuth.Store.FireDAC.Dialect;

type
  TFireDACUserRepository = class(TInterfacedObject, IUserRepository)
  private
    FFactory: IFireDACConnectionFactory;
    FDialect: TSqlDialect;

  public
    constructor Create(const Factory: IFireDACConnectionFactory; const Dialect: TSqlDialect);

    function TryGet(const UserId: string; out User: TAuthUser): Boolean;
    procedure Save(const User: TAuthUser);
  end;

implementation

uses
  MCPAuth.Store.FireDAC.Command;

const
  SelectUser = 'SELECT id, display_name, created_at FROM mcpauth_users WHERE id = :id';

{ TFireDACUserRepository }

constructor TFireDACUserRepository.Create(const Factory: IFireDACConnectionFactory; const Dialect: TSqlDialect);
begin
  inherited Create;
  FFactory := Factory;
  FDialect := Dialect;
end;

function TFireDACUserRepository.TryGet(const UserId: string; out User: TAuthUser): Boolean;
begin
  User := Default(TAuthUser);

  const Command = TFireDACCommand.Create(FFactory, SelectUser);
  try
    Command.SetText('id', UserId);
    Command.Open;

    Result := not Command.Eof;
    if Result then
    begin
      User.Id := Command.Text('id');
      User.DisplayName := Command.Text('display_name');
      User.CreatedAtUtc := Command.Utc('created_at');
    end;
  finally
    Command.Free;
  end;
end;

procedure TFireDACUserRepository.Save(const User: TAuthUser);
begin
  const Sql = FDialect.Upsert('mcpauth_users', 'id', ['id', 'display_name', 'created_at']);
  const Command = TFireDACCommand.Create(FFactory, Sql);
  try
    Command.SetText('id', User.Id);
    Command.SetText('display_name', User.DisplayName);
    Command.SetUtc('created_at', User.CreatedAtUtc);
    Command.Execute;
  finally
    Command.Free;
  end;
end;

end.
