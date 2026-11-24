unit MCPAuth.Store.FireDAC.LoginIdentities;

interface

uses
  Spring.Collections,
  MCPAuth.Identity.Types,
  MCPAuth.Identity.Interfaces,
  MCPAuth.Store.FireDAC.Interfaces,
  MCPAuth.Store.FireDAC.Command;

type
  // The unique index on identity_key keeps one user per login identity, also when two saves race.
  TFireDACLoginIdentityRepository = class(TInterfacedObject, ILoginIdentityRepository)
  private
    FFactory: IFireDACConnectionFactory;

    // Returns the number of affected rows: zero when another user owns the key.
    function Upsert(const Identity: TLoginIdentity): Integer;
    function ReadIdentity(const Command: TFireDACCommand): TLoginIdentity;

  public
    constructor Create(const Factory: IFireDACConnectionFactory);

    function TryFind(const Key: TAccountKey; out Identity: TLoginIdentity): Boolean;
    function ListForUser(const UserId: string): IReadOnlyList<TLoginIdentity>;

    procedure Save(const Identity: TLoginIdentity);

    // Gives every user without a login identity his oldest linked account as identity, skipping keys that already
    // are an identity. A release before login identities may have created such users after migration 0004 ran.
    // Returns the number of identities added.
    function AddMissing: Integer;
  end;

implementation

uses
  MCPAuth.Identity.Exceptions;

const
  SelectColumns = 'SELECT provider, tenant_id, object_id, user_id, user_name, created_at, last_login_at FROM mcpauth_login_identities ';
  SelectByKey = SelectColumns + 'WHERE identity_key = :identity_key';
  SelectByUser = SelectColumns + 'WHERE user_id = :user_id ORDER BY created_at, identity_key';
  // The update only applies to the identity of the same user; zero affected rows means another user owns the key.
  UpsertIdentity = 'INSERT INTO mcpauth_login_identities (identity_key, provider, tenant_id, object_id, user_id, user_name, created_at, ' +
                   'last_login_at) VALUES (:identity_key, :provider, :tenant_id, :object_id, :user_id, :user_name, :created_at, ' +
                   ':last_login_at) ON CONFLICT (identity_key) DO UPDATE SET user_name = EXCLUDED.user_name, ' +
                   'last_login_at = EXCLUDED.last_login_at WHERE mcpauth_login_identities.user_id = EXCLUDED.user_id';
  // Same statement as the backfill in migration 0004.
  InsertMissingIdentities = 'INSERT INTO mcpauth_login_identities (identity_key, provider, tenant_id, object_id, user_id, user_name, ' +
                            'created_at, last_login_at) SELECT DISTINCT ON (a.user_id) a.account_key, a.provider, a.tenant_id, ' +
                            'a.object_id, a.user_id, a.user_name, a.linked_at, a.updated_at FROM mcpauth_linked_accounts a ' +
                            'WHERE NOT EXISTS (SELECT 1 FROM mcpauth_login_identities i WHERE i.user_id = a.user_id) ' +
                            'ORDER BY a.user_id, a.linked_at, a.id ON CONFLICT (identity_key) DO NOTHING';

{ TFireDACLoginIdentityRepository }

constructor TFireDACLoginIdentityRepository.Create(const Factory: IFireDACConnectionFactory);
begin
  inherited Create;
  FFactory := Factory;
end;

function TFireDACLoginIdentityRepository.TryFind(const Key: TAccountKey; out Identity: TLoginIdentity): Boolean;
begin
  Identity := Default(TLoginIdentity);

  const Command = TFireDACCommand.Create(FFactory, SelectByKey);
  try
    Command.SetText('identity_key', Key.Value);
    Command.Open;

    Result := not Command.Eof;
    if Result then
    begin
      Identity := ReadIdentity(Command);
    end;
  finally
    Command.Free;
  end;
end;

function TFireDACLoginIdentityRepository.ListForUser(const UserId: string): IReadOnlyList<TLoginIdentity>;
begin
  const Identities = TCollections.CreateList<TLoginIdentity>;

  const Command = TFireDACCommand.Create(FFactory, SelectByUser);
  try
    Command.SetText('user_id', UserId);
    Command.Open;

    while not Command.Eof do
    begin
      Identities.Add(ReadIdentity(Command));
      Command.Next;
    end;
  finally
    Command.Free;
  end;

  Result := Identities.AsReadOnly;
end;

procedure TFireDACLoginIdentityRepository.Save(const Identity: TLoginIdentity);
begin
  const IsOtherUsersIdentity = (Upsert(Identity) = 0);
  if IsOtherUsersIdentity then
  begin
    raise ELoginIdentityTaken.Create('The account is already the login identity of another user');
  end;
end;

function TFireDACLoginIdentityRepository.Upsert(const Identity: TLoginIdentity): Integer;
begin
  const Command = TFireDACCommand.Create(FFactory, UpsertIdentity);
  try
    Command.SetText('identity_key', Identity.Key.Value);
    Command.SetText('provider', Identity.Key.Provider);
    Command.SetText('tenant_id', Identity.Key.TenantId);
    Command.SetText('object_id', Identity.Key.ObjectId);
    Command.SetText('user_id', Identity.UserId);
    Command.SetText('user_name', Identity.UserName);
    Command.SetUtc('created_at', Identity.CreatedAtUtc);
    Command.SetUtc('last_login_at', Identity.LastLoginAtUtc);
    Result := Command.Execute;
  finally
    Command.Free;
  end;
end;

function TFireDACLoginIdentityRepository.AddMissing: Integer;
begin
  const Command = TFireDACCommand.Create(FFactory, InsertMissingIdentities);
  try
    Result := Command.Execute;
  finally
    Command.Free;
  end;
end;

function TFireDACLoginIdentityRepository.ReadIdentity(const Command: TFireDACCommand): TLoginIdentity;
begin
  Result.Key.Provider   := Command.Text('provider');
  Result.Key.TenantId   := Command.Text('tenant_id');
  Result.Key.ObjectId   := Command.Text('object_id');
  Result.UserId         := Command.Text('user_id');
  Result.UserName       := Command.Text('user_name');
  Result.CreatedAtUtc   := Command.Utc('created_at');
  Result.LastLoginAtUtc := Command.Utc('last_login_at');
end;

end.
