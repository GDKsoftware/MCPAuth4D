unit MCPAuth.Store.FireDAC.LinkedAccounts;

interface

uses
  Spring.Collections,
  MCPAuth.Identity.Types,
  MCPAuth.Identity.Interfaces,
  MCPAuth.Store.FireDAC.Interfaces,
  MCPAuth.Store.FireDAC.Command;

type
  // The unique index on (user_id, account_key) keeps one row per user and upstream account, also when two saves race.
  TFireDACLinkedAccountRepository = class(TInterfacedObject, ILinkedAccountRepository)
  private
    FFactory: IFireDACConnectionFactory;

    procedure SetAccountParams(const Command: TFireDACCommand; const Account: TLinkedAccount);
    function ReadAccount(const Command: TFireDACCommand): TLinkedAccount;

  public
    constructor Create(const Factory: IFireDACConnectionFactory);

    function TryFind(const UserId: string; const Key: TAccountKey; out Account: TLinkedAccount): Boolean;
    function ListForUser(const UserId: string): IReadOnlyList<TLinkedAccount>;

    procedure Save(const Account: TLinkedAccount);
    procedure Delete(const UserId: string; const Key: TAccountKey);
  end;

implementation

uses
  System.SysUtils;

const
  SelectColumns = 'SELECT provider, tenant_id, object_id, user_id, display_name, user_name, granted_scopes, ' +
                  'protected_refresh_token, needs_reconnect, linked_at, updated_at FROM mcpauth_linked_accounts ';
  SelectByKey = SelectColumns + 'WHERE user_id = :user_id AND account_key = :account_key';
  SelectByUser = SelectColumns + 'WHERE user_id = :user_id ORDER BY linked_at, account_key';
  UpsertAccount = 'INSERT INTO mcpauth_linked_accounts (account_key, provider, tenant_id, object_id, user_id, display_name, ' +
                  'user_name, granted_scopes, protected_refresh_token, needs_reconnect, linked_at, updated_at) VALUES ' +
                  '(:account_key, :provider, :tenant_id, :object_id, :user_id, :display_name, :user_name, :granted_scopes, ' +
                  ':protected_refresh_token, :needs_reconnect, :linked_at, :updated_at) ON CONFLICT (user_id, account_key) ' +
                  'DO UPDATE SET provider = EXCLUDED.provider, tenant_id = EXCLUDED.tenant_id, object_id = EXCLUDED.object_id, ' +
                  'display_name = EXCLUDED.display_name, user_name = EXCLUDED.user_name, granted_scopes = EXCLUDED.granted_scopes, ' +
                  'protected_refresh_token = EXCLUDED.protected_refresh_token, needs_reconnect = EXCLUDED.needs_reconnect, ' +
                  'linked_at = EXCLUDED.linked_at, updated_at = EXCLUDED.updated_at';
  DeleteAccount = 'DELETE FROM mcpauth_linked_accounts WHERE account_key = :account_key AND user_id = :user_id';

{ TFireDACLinkedAccountRepository }

constructor TFireDACLinkedAccountRepository.Create(const Factory: IFireDACConnectionFactory);
begin
  inherited Create;
  FFactory := Factory;
end;

function TFireDACLinkedAccountRepository.TryFind(const UserId: string; const Key: TAccountKey; out Account: TLinkedAccount): Boolean;
begin
  Account := Default(TLinkedAccount);

  const Command = TFireDACCommand.Create(FFactory, SelectByKey);
  try
    Command.SetText('user_id', UserId);
    Command.SetText('account_key', Key.Value);
    Command.Open;

    Result := not Command.Eof;
    if Result then
    begin
      Account := ReadAccount(Command);
    end;
  finally
    Command.Free;
  end;
end;

function TFireDACLinkedAccountRepository.ListForUser(const UserId: string): IReadOnlyList<TLinkedAccount>;
begin
  const Accounts = TCollections.CreateList<TLinkedAccount>;

  const Command = TFireDACCommand.Create(FFactory, SelectByUser);
  try
    Command.SetText('user_id', UserId);
    Command.Open;

    while not Command.Eof do
    begin
      Accounts.Add(ReadAccount(Command));
      Command.Next;
    end;
  finally
    Command.Free;
  end;

  Result := Accounts.AsReadOnly;
end;

procedure TFireDACLinkedAccountRepository.Save(const Account: TLinkedAccount);
begin
  const Command = TFireDACCommand.Create(FFactory, UpsertAccount);
  try
    SetAccountParams(Command, Account);
    Command.Execute;
  finally
    Command.Free;
  end;
end;

procedure TFireDACLinkedAccountRepository.Delete(const UserId: string; const Key: TAccountKey);
begin
  const Command = TFireDACCommand.Create(FFactory, DeleteAccount);
  try
    Command.SetText('account_key', Key.Value);
    Command.SetText('user_id', UserId);
    Command.Execute;
  finally
    Command.Free;
  end;
end;

procedure TFireDACLinkedAccountRepository.SetAccountParams(const Command: TFireDACCommand; const Account: TLinkedAccount);
begin
  Command.SetText('account_key', Account.Key.Value);
  Command.SetText('provider', Account.Key.Provider);
  Command.SetText('tenant_id', Account.Key.TenantId);
  Command.SetText('object_id', Account.Key.ObjectId);
  Command.SetText('user_id', Account.UserId);
  Command.SetText('display_name', Account.DisplayName);
  Command.SetText('user_name', Account.UserName);
  Command.SetText('granted_scopes', Account.GrantedScopes);
  Command.SetBytes('protected_refresh_token', Account.ProtectedRefreshToken);
  Command.SetFlag('needs_reconnect', Account.NeedsReconnect);
  Command.SetUtc('linked_at', Account.LinkedAtUtc);
  Command.SetUtc('updated_at', Account.UpdatedAtUtc);
end;

function TFireDACLinkedAccountRepository.ReadAccount(const Command: TFireDACCommand): TLinkedAccount;
begin
  Result.Key.Provider := Command.Text('provider');
  Result.Key.TenantId := Command.Text('tenant_id');
  Result.Key.ObjectId := Command.Text('object_id');
  Result.UserId := Command.Text('user_id');
  Result.DisplayName := Command.Text('display_name');
  Result.UserName := Command.Text('user_name');
  Result.GrantedScopes := Command.Text('granted_scopes');
  Result.ProtectedRefreshToken := Command.Bytes('protected_refresh_token');
  Result.NeedsReconnect := Command.Flag('needs_reconnect');
  Result.LinkedAtUtc := Command.Utc('linked_at');
  Result.UpdatedAtUtc := Command.Utc('updated_at');
end;

end.
