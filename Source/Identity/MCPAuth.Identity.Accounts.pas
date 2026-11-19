unit MCPAuth.Identity.Accounts;

interface

uses
  MCPAuth.Clock.Interfaces,
  MCPAuth.Secret.Interfaces,
  MCPAuth.Identity.Types,
  MCPAuth.Identity.Interfaces,
  MCPAuth.Identity.Access.Interfaces,
  MCPAuth.Upstream.Types;

type
  TLinkedAccounts = class(TInterfacedObject, ILinkedAccounts)
  private
    FUsers: IUserRepository;
    FAccounts: ILinkedAccountRepository;
    FProtector: ISecretProtector;
    FPolicy: IAccessPolicy;
    FClock: IClock;

    class function NewUserId: string; static;
    class function RefreshTokenContext(const UserId: string; const Key: TAccountKey): string; static;

    procedure GuardAllowed(const Identity: TUpstreamIdentity);
    function GetUser(const UserId: string): TAuthUser;
    function CreateUser(const Identity: TUpstreamIdentity): TAuthUser;
    function SaveAccount(const UserId: string; const Tokens: TUpstreamTokens): TLinkedAccount;

  public
    constructor Create(const Users: IUserRepository; const Accounts: ILinkedAccountRepository; const Protector: ISecretProtector; const Policy: IAccessPolicy; const Clock: IClock);

    function ResolveOrCreateUser(const Tokens: TUpstreamTokens): TAuthUser;
    function Link(const UserId: string; const Tokens: TUpstreamTokens): TLinkedAccount;
  end;

implementation

uses
  System.SysUtils,
  MCPAuth.Identity.Exceptions;

{ TLinkedAccounts }

class function TLinkedAccounts.NewUserId: string;
begin
  const Guid = TGUID.NewGuid;
  const GuidText = Guid.ToString;

  Result := GuidText.Substring(1, GuidText.Length - 2);
end;

class function TLinkedAccounts.RefreshTokenContext(const UserId: string; const Key: TAccountKey): string;
begin
  Result := Format('%s|%s', [UserId, Key.Value]);
end;

constructor TLinkedAccounts.Create(const Users: IUserRepository; const Accounts: ILinkedAccountRepository; const Protector: ISecretProtector; const Policy: IAccessPolicy; const Clock: IClock);
begin
  inherited Create;

  FUsers := Users;
  FAccounts := Accounts;
  FProtector := Protector;
  FPolicy := Policy;
  FClock := Clock;
end;

function TLinkedAccounts.ResolveOrCreateUser(const Tokens: TUpstreamTokens): TAuthUser;
begin
  GuardAllowed(Tokens.Identity);

  var Existing: TLinkedAccount;
  const IsKnownAccount = FAccounts.TryFind(Tokens.Identity.Key, Existing);
  if IsKnownAccount then
  begin
    Result := GetUser(Existing.UserId);
  end
  else
  begin
    Result := CreateUser(Tokens.Identity);
  end;

  SaveAccount(Result.Id, Tokens);
end;

function TLinkedAccounts.Link(const UserId: string; const Tokens: TUpstreamTokens): TLinkedAccount;
begin
  GuardAllowed(Tokens.Identity);
  GetUser(UserId);

  var Existing: TLinkedAccount;
  const IsKnownAccount = FAccounts.TryFind(Tokens.Identity.Key, Existing);
  const IsOtherUsersAccount = (IsKnownAccount and (Existing.UserId <> UserId));
  if IsOtherUsersAccount then
    raise EAccountLinkedToOtherUser.Create('The account is already linked to another user');

  Result := SaveAccount(UserId, Tokens);
end;

procedure TLinkedAccounts.GuardAllowed(const Identity: TUpstreamIdentity);
begin
  if not FPolicy.IsAllowed(Identity) then
    raise EAccessDenied.Create('This account is not allowed to sign in');
end;

function TLinkedAccounts.GetUser(const UserId: string): TAuthUser;
begin
  if not FUsers.TryGet(UserId, Result) then
    raise EUserNotFound.Create('The user does not exist');
end;

function TLinkedAccounts.CreateUser(const Identity: TUpstreamIdentity): TAuthUser;
begin
  Result := Default(TAuthUser);
  Result.Id           := NewUserId;
  Result.DisplayName  := Identity.DisplayName;
  Result.CreatedAtUtc := FClock.NowUtc;

  FUsers.Save(Result);
end;

function TLinkedAccounts.SaveAccount(const UserId: string; const Tokens: TUpstreamTokens): TLinkedAccount;
begin
  const NowUtc = FClock.NowUtc;
  const Key = Tokens.Identity.Key;

  const IsKnownAccount = FAccounts.TryFind(Key, Result);
  if not IsKnownAccount then
  begin
    Result := Default(TLinkedAccount);
    Result.Key := Key;
    Result.LinkedAtUtc := NowUtc;
  end;

  Result.UserId         := UserId;
  Result.DisplayName    := Tokens.Identity.DisplayName;
  Result.UserName       := Tokens.Identity.UserName;
  Result.GrantedScopes  := Tokens.Scope;
  Result.NeedsReconnect := False;
  Result.UpdatedAtUtc   := NowUtc;

  // A provider may leave out the refresh token; the stored one then stays valid.
  const HasRefreshToken = not Tokens.RefreshToken.IsEmpty;
  if HasRefreshToken then
  begin
    const Context = RefreshTokenContext(UserId, Key);
    Result.ProtectedRefreshToken := FProtector.Protect(Tokens.RefreshToken, Context);
  end;

  FAccounts.Save(Result);
end;

end.
