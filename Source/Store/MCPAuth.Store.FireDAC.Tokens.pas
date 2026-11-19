unit MCPAuth.Store.FireDAC.Tokens;

interface

uses
  Spring.Collections,
  MCPAuth.Clock.Interfaces,
  MCPAuth.OAuth.Types,
  MCPAuth.OAuth.Interfaces,
  MCPAuth.Store.FireDAC.Interfaces,
  MCPAuth.Store.FireDAC.Dialect,
  MCPAuth.Store.FireDAC.Command;

type
  TFireDACTokenRepository = class(TInterfacedObject, ITokenRepository)
  private
    FFactory: IFireDACConnectionFactory;
    FDialect: TSqlDialect;
    FClock: IClock;

    class function KindToText(const Kind: TTokenKind): string; static;
    class function TextToKind(const Text: string): TTokenKind; static;

    function ReadToken(const Command: TFireDACCommand): TIssuedToken;
    procedure DeleteWhere(const Column, Value: string);

  public
    constructor Create(const Factory: IFireDACConnectionFactory; const Dialect: TSqlDialect; const Clock: IClock);

    function TryGet(const Hash: string; out Token: TIssuedToken): Boolean;
    procedure Save(const Token: TIssuedToken);
    function TryConsume(const Hash: string; out Token: TIssuedToken): Boolean;

    function IsKnownConsumed(const Hash: string; out FamilyId: string): Boolean;
    procedure DeleteFamily(const FamilyId: string);
    procedure DeleteForUser(const UserId: string);
    function ListFamiliesForUser(const UserId: string): IReadOnlyList<TGrantedFamily>;
    function HasActiveFamily(const UserId, Resource: string): Boolean;
    function DeleteExpired(const NowUtc: TDateTime): Integer;
  end;

implementation

uses
  System.SysUtils,
  MCPAuth.Store.FireDAC.Exceptions;

const
  Table = 'mcpauth_tokens';
  Columns: TArray<string> = ['hash', 'kind', 'family_id', 'user_id', 'client_id', 'scope', 'resource', 'consumed', 'created_at', 'expires_at'];
  AccessText = 'access';
  RefreshText = 'refresh';

  SelectConsumedFamily = 'SELECT family_id FROM mcpauth_tokens WHERE hash = :hash AND consumed = true';
  ActiveTokenCondition = 'consumed = false AND expires_at > :now';
  SelectActiveFamilies = 'SELECT family_id, user_id, client_id, resource, created_at FROM mcpauth_tokens ' +
                         'WHERE user_id = :user_id AND ' + ActiveTokenCondition + ' ORDER BY family_id, created_at';
  CountActiveForResource = 'SELECT COUNT(*) AS active_count FROM mcpauth_tokens ' +
                           'WHERE user_id = :user_id AND resource = :resource AND ' + ActiveTokenCondition;
  DeleteExpiredTokens = 'DELETE FROM mcpauth_tokens WHERE expires_at <= :now';

{ TFireDACTokenRepository }

class function TFireDACTokenRepository.KindToText(const Kind: TTokenKind): string;
begin
  case Kind of
    TTokenKind.Access:  Result := AccessText;
    TTokenKind.Refresh: Result := RefreshText;
  else
    raise EFireDACStoreError.CreateFmt('Unknown token kind %d', [Ord(Kind)]);
  end;
end;

class function TFireDACTokenRepository.TextToKind(const Text: string): TTokenKind;
begin
  if Text = AccessText then
  begin
    Result := TTokenKind.Access;
  end
  else if Text = RefreshText then
  begin
    Result := TTokenKind.Refresh;
  end
  else
  begin
    raise EFireDACStoreError.CreateFmt('Unknown stored token kind "%s"', [Text]);
  end;
end;

constructor TFireDACTokenRepository.Create(const Factory: IFireDACConnectionFactory; const Dialect: TSqlDialect; const Clock: IClock);
begin
  inherited Create;
  FFactory := Factory;
  FDialect := Dialect;
  FClock := Clock;
end;

function TFireDACTokenRepository.TryGet(const Hash: string; out Token: TIssuedToken): Boolean;
begin
  Token := Default(TIssuedToken);

  const Sql = Format('SELECT %s FROM %s WHERE hash = :hash AND expires_at > :now', [string.Join(', ', Columns), Table]);
  const Command = TFireDACCommand.Create(FFactory, Sql);
  try
    Command.SetText('hash', Hash);
    Command.SetUtc('now', FClock.NowUtc);
    Command.Open;

    Result := not Command.Eof;
    if Result then
    begin
      Token := ReadToken(Command);
    end;
  finally
    Command.Free;
  end;
end;

procedure TFireDACTokenRepository.Save(const Token: TIssuedToken);
begin
  const Command = TFireDACCommand.Create(FFactory, FDialect.Upsert(Table, 'hash', Columns));
  try
    Command.SetText('hash', Token.Hash);
    Command.SetText('kind', KindToText(Token.Kind));
    Command.SetText('family_id', Token.FamilyId);
    Command.SetText('user_id', Token.UserId);
    Command.SetText('client_id', Token.ClientId);
    Command.SetText('scope', Token.Scope);
    Command.SetText('resource', Token.Resource);
    Command.SetFlag('consumed', Token.Consumed);
    Command.SetUtc('created_at', Token.CreatedAtUtc);
    Command.SetUtc('expires_at', Token.ExpiresAtUtc);
    Command.Execute;
  finally
    Command.Free;
  end;
end;

function TFireDACTokenRepository.TryConsume(const Hash: string; out Token: TIssuedToken): Boolean;
begin
  Token := Default(TIssuedToken);

  // One statement, so two concurrent callers can never both consume the token.
  const Update = Format('UPDATE %s SET consumed = true WHERE hash = :hash AND %s', [Table, ActiveTokenCondition]);
  const Command = TFireDACCommand.Create(FFactory, FDialect.Returning(Update, Columns));
  try
    Command.SetText('hash', Hash);
    Command.SetUtc('now', FClock.NowUtc);
    Command.Open;

    Result := not Command.Eof;
    if Result then
    begin
      Token := ReadToken(Command);
    end;
  finally
    Command.Free;
  end;
end;

function TFireDACTokenRepository.IsKnownConsumed(const Hash: string; out FamilyId: string): Boolean;
begin
  FamilyId := '';

  const Command = TFireDACCommand.Create(FFactory, SelectConsumedFamily);
  try
    Command.SetText('hash', Hash);
    Command.Open;

    Result := not Command.Eof;
    if Result then
    begin
      FamilyId := Command.Text('family_id');
    end;
  finally
    Command.Free;
  end;
end;

procedure TFireDACTokenRepository.DeleteFamily(const FamilyId: string);
begin
  DeleteWhere('family_id', FamilyId);
end;

procedure TFireDACTokenRepository.DeleteForUser(const UserId: string);
begin
  DeleteWhere('user_id', UserId);
end;

function TFireDACTokenRepository.ListFamiliesForUser(const UserId: string): IReadOnlyList<TGrantedFamily>;
begin
  const Families = TCollections.CreateList<TGrantedFamily>;

  // Rows come ordered by family and creation time; the first row of each family describes it.
  const Command = TFireDACCommand.Create(FFactory, SelectActiveFamilies);
  try
    Command.SetText('user_id', UserId);
    Command.SetUtc('now', FClock.NowUtc);
    Command.Open;

    var PreviousFamilyId := '';
    while not Command.Eof do
    begin
      const FamilyId = Command.Text('family_id');
      const IsNewFamily = (Families.IsEmpty or (FamilyId <> PreviousFamilyId));
      if IsNewFamily then
      begin
        var Family: TGrantedFamily;
        Family.FamilyId := FamilyId;
        Family.UserId := Command.Text('user_id');
        Family.ClientId := Command.Text('client_id');
        Family.Resource := Command.Text('resource');
        Family.CreatedAtUtc := Command.Utc('created_at');
        Families.Add(Family);
        PreviousFamilyId := FamilyId;
      end;
      Command.Next;
    end;
  finally
    Command.Free;
  end;

  Result := Families.AsReadOnly;
end;

function TFireDACTokenRepository.HasActiveFamily(const UserId, Resource: string): Boolean;
begin
  const Command = TFireDACCommand.Create(FFactory, CountActiveForResource);
  try
    Command.SetText('user_id', UserId);
    Command.SetText('resource', Resource);
    Command.SetUtc('now', FClock.NowUtc);
    Command.Open;

    Result := (Command.Int('active_count') > 0);
  finally
    Command.Free;
  end;
end;

function TFireDACTokenRepository.DeleteExpired(const NowUtc: TDateTime): Integer;
begin
  const Command = TFireDACCommand.Create(FFactory, DeleteExpiredTokens);
  try
    Command.SetUtc('now', NowUtc);
    Result := Command.Execute;
  finally
    Command.Free;
  end;
end;

function TFireDACTokenRepository.ReadToken(const Command: TFireDACCommand): TIssuedToken;
begin
  Result.Hash := Command.Text('hash');
  Result.Kind := TextToKind(Command.Text('kind'));
  Result.FamilyId := Command.Text('family_id');
  Result.UserId := Command.Text('user_id');
  Result.ClientId := Command.Text('client_id');
  Result.Scope := Command.Text('scope');
  Result.Resource := Command.Text('resource');
  Result.Consumed := Command.Flag('consumed');
  Result.CreatedAtUtc := Command.Utc('created_at');
  Result.ExpiresAtUtc := Command.Utc('expires_at');
end;

procedure TFireDACTokenRepository.DeleteWhere(const Column, Value: string);
begin
  const Command = TFireDACCommand.Create(FFactory, Format('DELETE FROM %s WHERE %s = :value', [Table, Column]));
  try
    Command.SetText('value', Value);
    Command.Execute;
  finally
    Command.Free;
  end;
end;

end.
