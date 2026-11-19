unit MCPAuth.Store.FireDAC.PendingAuthorizations;

interface

uses
  MCPAuth.Clock.Interfaces,
  MCPAuth.OAuth.Types,
  MCPAuth.OAuth.Interfaces,
  MCPAuth.Store.FireDAC.Interfaces,
  MCPAuth.Store.FireDAC.Dialect,
  MCPAuth.Store.FireDAC.Command;

type
  TFireDACPendingAuthorizationStore = class(TInterfacedObject, IPendingAuthorizationStore)
  private
    FFactory: IFireDACConnectionFactory;
    FDialect: TSqlDialect;
    FClock: IClock;

    class function PurposeToText(const Purpose: TLoginPurpose): string; static;
    class function TextToPurpose(const Text: string): TLoginPurpose; static;

    function ReadPending(const Command: TFireDACCommand): TPendingAuthorization;

  public
    constructor Create(const Factory: IFireDACConnectionFactory; const Dialect: TSqlDialect; const Clock: IClock);

    procedure Put(const Pending: TPendingAuthorization);
    function TryGet(const Id: string; out Pending: TPendingAuthorization): Boolean;
    function TryTake(const Id: string; out Pending: TPendingAuthorization): Boolean;
  end;

implementation

uses
  System.SysUtils,
  MCPAuth.Store.FireDAC.Exceptions;

const
  Table = 'mcpauth_pending_authorizations';
  Columns: TArray<string> = ['id', 'purpose', 'client_id', 'redirect_uri', 'code_challenge', 'state', 'scope', 'resource',
                             'user_id', 'upstream_provider', 'upstream_verifier', 'expires_at'];
  AuthorizeText = 'authorize';
  LinkAccountText = 'link_account';
  PortalText = 'portal';

{ TFireDACPendingAuthorizationStore }

class function TFireDACPendingAuthorizationStore.PurposeToText(const Purpose: TLoginPurpose): string;
begin
  case Purpose of
    TLoginPurpose.Authorize:   Result := AuthorizeText;
    TLoginPurpose.LinkAccount: Result := LinkAccountText;
    TLoginPurpose.Portal:      Result := PortalText;
  else
    raise EFireDACStoreError.CreateFmt('Unknown login purpose %d', [Ord(Purpose)]);
  end;
end;

class function TFireDACPendingAuthorizationStore.TextToPurpose(const Text: string): TLoginPurpose;
begin
  if Text = AuthorizeText then
  begin
    Result := TLoginPurpose.Authorize;
  end
  else if Text = LinkAccountText then
  begin
    Result := TLoginPurpose.LinkAccount;
  end
  else if Text = PortalText then
  begin
    Result := TLoginPurpose.Portal;
  end
  else
  begin
    raise EFireDACStoreError.CreateFmt('Unknown stored login purpose "%s"', [Text]);
  end;
end;

constructor TFireDACPendingAuthorizationStore.Create(const Factory: IFireDACConnectionFactory; const Dialect: TSqlDialect; const Clock: IClock);
begin
  inherited Create;
  FFactory := Factory;
  FDialect := Dialect;
  FClock := Clock;
end;

procedure TFireDACPendingAuthorizationStore.Put(const Pending: TPendingAuthorization);
begin
  const Command = TFireDACCommand.Create(FFactory, FDialect.Upsert(Table, 'id', Columns));
  try
    Command.SetText('id', Pending.Id);
    Command.SetText('purpose', PurposeToText(Pending.Purpose));
    Command.SetText('client_id', Pending.ClientId);
    Command.SetText('redirect_uri', Pending.RedirectUri);
    Command.SetText('code_challenge', Pending.CodeChallenge);
    Command.SetText('state', Pending.State);
    Command.SetText('scope', Pending.Scope);
    Command.SetText('resource', Pending.Resource);
    Command.SetText('user_id', Pending.UserId);
    Command.SetText('upstream_provider', Pending.UpstreamProvider);
    Command.SetText('upstream_verifier', Pending.UpstreamVerifier);
    Command.SetUtc('expires_at', Pending.ExpiresAtUtc);
    Command.Execute;
  finally
    Command.Free;
  end;
end;

function TFireDACPendingAuthorizationStore.TryGet(const Id: string; out Pending: TPendingAuthorization): Boolean;
begin
  Pending := Default(TPendingAuthorization);

  const Sql = Format('SELECT %s FROM %s WHERE id = :id AND expires_at > :now', [string.Join(', ', Columns), Table]);
  const Command = TFireDACCommand.Create(FFactory, Sql);
  try
    Command.SetText('id', Id);
    Command.SetUtc('now', FClock.NowUtc);
    Command.Open;

    Result := not Command.Eof;
    if Result then
    begin
      Pending := ReadPending(Command);
    end;
  finally
    Command.Free;
  end;
end;

function TFireDACPendingAuthorizationStore.TryTake(const Id: string; out Pending: TPendingAuthorization): Boolean;
begin
  Pending := Default(TPendingAuthorization);

  // An expired entry is removed as well, but counts as absent.
  const Sql = FDialect.Returning(Format('DELETE FROM %s WHERE id = :id', [Table]), Columns);
  const Command = TFireDACCommand.Create(FFactory, Sql);
  try
    Command.SetText('id', Id);
    Command.Open;

    const IsFound = not Command.Eof;
    if IsFound then
    begin
      Pending := ReadPending(Command);
    end;
    Result := (IsFound and (Pending.ExpiresAtUtc > FClock.NowUtc));
  finally
    Command.Free;
  end;
end;

function TFireDACPendingAuthorizationStore.ReadPending(const Command: TFireDACCommand): TPendingAuthorization;
begin
  Result.Id := Command.Text('id');
  Result.Purpose := TextToPurpose(Command.Text('purpose'));
  Result.ClientId := Command.Text('client_id');
  Result.RedirectUri := Command.Text('redirect_uri');
  Result.CodeChallenge := Command.Text('code_challenge');
  Result.State := Command.Text('state');
  Result.Scope := Command.Text('scope');
  Result.Resource := Command.Text('resource');
  Result.UserId := Command.Text('user_id');
  Result.UpstreamProvider := Command.Text('upstream_provider');
  Result.UpstreamVerifier := Command.Text('upstream_verifier');
  Result.ExpiresAtUtc := Command.Utc('expires_at');
end;

end.
