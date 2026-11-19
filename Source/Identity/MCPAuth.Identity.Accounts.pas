unit MCPAuth.Identity.Accounts;

interface

uses
  System.SyncObjs,
  Spring.Collections,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Secret.Interfaces,
  MCPAuth.Identity.Types,
  MCPAuth.Identity.Interfaces,
  MCPAuth.Identity.Access.Interfaces,
  MCPAuth.Upstream.Types,
  MCPAuth.Upstream.Interfaces;

type
  TLinkedAccounts = class(TInterfacedObject, ILinkedAccounts)
  private
    FUsers: IUserRepository;
    FAccounts: ILinkedAccountRepository;
    FProtector: ISecretProtector;
    FPolicy: IAccessPolicy;
    FProviders: IUpstreamProviders;
    FClock: IClock;
    FTokenCache: IDictionary<string, TUpstreamAccessToken>;
    FCacheLock: TCriticalSection;
    FAccountLocks: IDictionary<string, TCriticalSection>;
    FAccountLocksLock: TCriticalSection;

    class function NewUserId: string; static;
    class function RefreshTokenContext(const UserId: string; const Key: TAccountKey): string; static;
    class function AccountLockName(const Key: TAccountKey): string; static;
    class function UserLockName(const UserId: string): string; static;

    function ResolveOrCreateUserLocked(const Tokens: TUpstreamTokens): TAuthUser;
    function LinkLocked(const UserId: string; const Tokens: TUpstreamTokens): TLinkedAccount;
    procedure UnlinkLocked(const UserId: string; const Key: TAccountKey);
    procedure GuardAllowed(const Identity: TUpstreamIdentity);
    function GetUser(const UserId: string): TAuthUser;
    function CreateUser(const Identity: TUpstreamIdentity): TAuthUser;
    function SaveAccount(const UserId: string; const Tokens: TUpstreamTokens): TLinkedAccount;

    function LockFor(const Context: string): TCriticalSection;
    function FindOwnAccount(const UserId: string; const Key: TAccountKey): TLinkedAccount;
    procedure GuardNotMarkedForReconnect(const Account: TLinkedAccount);
    procedure GuardScopesGranted(const Account: TLinkedAccount; const RequiredScopes: TArray<string>);
    function TryGetCachedToken(const Context: string; out Token: TUpstreamAccessToken): Boolean;
    procedure StoreCachedToken(const Context: string; const Token: TUpstreamAccessToken);
    procedure RemoveCachedToken(const Context: string);
    function RefreshAccessToken(const Account: TLinkedAccount; const Context: string): TUpstreamAccessToken;
    function RequestUpstreamTokens(const Account: TLinkedAccount; const RefreshToken: string): TUpstreamTokens;
    procedure MarkNeedsReconnect(const Account: TLinkedAccount; const Context: string);
    procedure StoreRefreshedAccount(const Account: TLinkedAccount; const Context, CurrentRefreshToken: string; const Tokens: TUpstreamTokens);

  public
    constructor Create(const Users: IUserRepository; const Accounts: ILinkedAccountRepository; const Protector: ISecretProtector; const Policy: IAccessPolicy; const Providers: IUpstreamProviders; const Clock: IClock);
    destructor Destroy; override;

    function ResolveOrCreateUser(const Tokens: TUpstreamTokens): TAuthUser;
    function Link(const UserId: string; const Tokens: TUpstreamTokens): TLinkedAccount;
    function ListForUser(const UserId: string): IReadOnlyList<TLinkedAccount>;
    function GetAccessToken(const UserId: string; const Key: TAccountKey; const RequiredScopes: TArray<string>): TUpstreamAccessToken;
    procedure Unlink(const UserId: string; const Key: TAccountKey);
  end;

implementation

uses
  System.SysUtils,
  System.StrUtils,
  System.DateUtils,
  MCPAuth.Identity.Exceptions,
  MCPAuth.Upstream.Exceptions;

const
  ExpiryMarginSeconds = 60;
  ReasonRevoked = 'revoked';
  ReasonMissingScopes = 'missing_scopes';
  AlwaysGrantedScopes: array[0..3] of string = ('openid', 'profile', 'offline_access', 'email');
  AccountLockFormat = 'account|%s';
  UserLockFormat = 'user|%s';

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

class function TLinkedAccounts.AccountLockName(const Key: TAccountKey): string;
begin
  Result := Format(AccountLockFormat, [Key.Value]);
end;

class function TLinkedAccounts.UserLockName(const UserId: string): string;
begin
  Result := Format(UserLockFormat, [UserId]);
end;

constructor TLinkedAccounts.Create(const Users: IUserRepository; const Accounts: ILinkedAccountRepository; const Protector: ISecretProtector; const Policy: IAccessPolicy; const Providers: IUpstreamProviders; const Clock: IClock);
begin
  inherited Create;

  FUsers := Users;
  FAccounts := Accounts;
  FProtector := Protector;
  FPolicy := Policy;
  FProviders := Providers;
  FClock := Clock;
  FTokenCache := TCollections.CreateDictionary<string, TUpstreamAccessToken>;
  FCacheLock := TCriticalSection.Create;
  FAccountLocks := TCollections.CreateDictionary<string, TCriticalSection>([doOwnsValues]);
  FAccountLocksLock := TCriticalSection.Create;
end;

destructor TLinkedAccounts.Destroy;
begin
  FAccountLocks := nil;
  FAccountLocksLock.Free;
  FCacheLock.Free;

  inherited;
end;

function TLinkedAccounts.ResolveOrCreateUser(const Tokens: TUpstreamTokens): TAuthUser;
begin
  GuardAllowed(Tokens.Identity);

  // Two first sign-ins of the same account at once would otherwise both create a user.
  const AccountLock = LockFor(AccountLockName(Tokens.Identity.Key));
  AccountLock.Enter;
  try
    Result := ResolveOrCreateUserLocked(Tokens);
  finally
    AccountLock.Leave;
  end;
end;

function TLinkedAccounts.ResolveOrCreateUserLocked(const Tokens: TUpstreamTokens): TAuthUser;
begin
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

  const AccountLock = LockFor(AccountLockName(Tokens.Identity.Key));
  AccountLock.Enter;
  try
    Result := LinkLocked(UserId, Tokens);
  finally
    AccountLock.Leave;
  end;
end;

function TLinkedAccounts.LinkLocked(const UserId: string; const Tokens: TUpstreamTokens): TLinkedAccount;
begin
  GetUser(UserId);

  var Existing: TLinkedAccount;
  const IsKnownAccount = FAccounts.TryFind(Tokens.Identity.Key, Existing);
  const IsOtherUsersAccount = (IsKnownAccount and (Existing.UserId <> UserId));
  if IsOtherUsersAccount then
    raise EAccountLinkedToOtherUser.Create('The account is already linked to another user');

  Result := SaveAccount(UserId, Tokens);
end;

function TLinkedAccounts.ListForUser(const UserId: string): IReadOnlyList<TLinkedAccount>;
begin
  Result := FAccounts.ListForUser(UserId);
end;

function TLinkedAccounts.GetAccessToken(const UserId: string; const Key: TAccountKey; const RequiredScopes: TArray<string>): TUpstreamAccessToken;
begin
  const Context = RefreshTokenContext(UserId, Key);

  const Account = FindOwnAccount(UserId, Key);
  GuardNotMarkedForReconnect(Account);
  GuardScopesGranted(Account, RequiredScopes);
  if TryGetCachedToken(Context, Result) then
    Exit;

  const AccountLock = LockFor(Context);
  AccountLock.Enter;
  try
    // A concurrent caller may have refreshed while this one waited for the lock.
    if TryGetCachedToken(Context, Result) then
      Exit;

    // Read again: the account may have changed or been removed in the meantime.
    const CurrentAccount = FindOwnAccount(UserId, Key);
    GuardNotMarkedForReconnect(CurrentAccount);
    Result := RefreshAccessToken(CurrentAccount, Context);
  finally
    AccountLock.Leave;
  end;
end;

procedure TLinkedAccounts.Unlink(const UserId: string; const Key: TAccountKey);
begin
  // The last-account check counts all accounts of the user, so concurrent unlinks of one user run one at a time.
  const UserLock = LockFor(UserLockName(UserId));
  UserLock.Enter;
  try
    UnlinkLocked(UserId, Key);
  finally
    UserLock.Leave;
  end;
end;

procedure TLinkedAccounts.UnlinkLocked(const UserId: string; const Key: TAccountKey);
begin
  const Context = RefreshTokenContext(UserId, Key);

  const AccountLock = LockFor(Context);
  AccountLock.Enter;
  try
    FindOwnAccount(UserId, Key);

    const IsLastAccount = (FAccounts.ListForUser(UserId).Count <= 1);
    if IsLastAccount then
      raise ELastAccountCannotBeUnlinked.Create('The last linked account of a user cannot be unlinked');

    FAccounts.Delete(UserId, Key);
    RemoveCachedToken(Context);
  finally
    AccountLock.Leave;
  end;
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

  Result.UserId       := UserId;
  Result.DisplayName  := Tokens.Identity.DisplayName;
  Result.UserName     := Tokens.Identity.UserName;
  Result.UpdatedAtUtc := NowUtc;

  // A provider may leave out the refresh token; the stored one then stays, and so do its scopes and
  // its reconnect flag, which describe that stored token.
  const HasRefreshToken = not Tokens.RefreshToken.IsEmpty;
  if HasRefreshToken or not IsKnownAccount then
  begin
    Result.GrantedScopes  := Tokens.Scope;
    Result.NeedsReconnect := False;
  end;

  if HasRefreshToken then
  begin
    const Context = RefreshTokenContext(UserId, Key);
    Result.ProtectedRefreshToken := FProtector.Protect(Tokens.RefreshToken, Context);
  end;

  FAccounts.Save(Result);
end;

function TLinkedAccounts.LockFor(const Context: string): TCriticalSection;
begin
  FAccountLocksLock.Enter;
  try
    if not FAccountLocks.TryGetValue(Context, Result) then
    begin
      Result := TCriticalSection.Create;
      FAccountLocks.Add(Context, Result);
    end;
  finally
    FAccountLocksLock.Leave;
  end;
end;

function TLinkedAccounts.FindOwnAccount(const UserId: string; const Key: TAccountKey): TLinkedAccount;
begin
  const IsOwnAccount = (FAccounts.TryFind(Key, Result) and (Result.UserId = UserId));
  if not IsOwnAccount then
    raise ELinkedAccountNotFound.Create('The linked account does not exist');
end;

procedure TLinkedAccounts.GuardNotMarkedForReconnect(const Account: TLinkedAccount);
begin
  if Account.NeedsReconnect then
    raise ELinkedAccountNeedsReconnect.Create(ReasonRevoked);
end;

procedure TLinkedAccounts.GuardScopesGranted(const Account: TLinkedAccount; const RequiredScopes: TArray<string>);
begin
  const Granted = Account.GrantedScopes.ToLowerInvariant.Split([' '], TStringSplitOptions.ExcludeEmpty);

  for var Scope in RequiredScopes do
  begin
    const Wanted = Scope.ToLowerInvariant;
    const IsAlwaysGranted = MatchStr(Wanted, AlwaysGrantedScopes);
    const IsGranted = (IsAlwaysGranted or MatchStr(Wanted, Granted));
    if not IsGranted then
      raise ELinkedAccountNeedsReconnect.Create(ReasonMissingScopes);
  end;
end;

function TLinkedAccounts.TryGetCachedToken(const Context: string; out Token: TUpstreamAccessToken): Boolean;
begin
  FCacheLock.Enter;
  try
    const ValidUntilUtc = IncSecond(FClock.NowUtc, ExpiryMarginSeconds);
    Result := (FTokenCache.TryGetValue(Context, Token) and (Token.ExpiresAtUtc > ValidUntilUtc));
  finally
    FCacheLock.Leave;
  end;
end;

procedure TLinkedAccounts.StoreCachedToken(const Context: string; const Token: TUpstreamAccessToken);
begin
  FCacheLock.Enter;
  try
    FTokenCache[Context] := Token;
  finally
    FCacheLock.Leave;
  end;
end;

procedure TLinkedAccounts.RemoveCachedToken(const Context: string);
begin
  FCacheLock.Enter;
  try
    FTokenCache.Remove(Context);
  finally
    FCacheLock.Leave;
  end;
end;

function TLinkedAccounts.RefreshAccessToken(const Account: TLinkedAccount; const Context: string): TUpstreamAccessToken;
begin
  const CurrentRefreshToken = FProtector.Unprotect(Account.ProtectedRefreshToken, Context);

  var Tokens: TUpstreamTokens;
  try
    Tokens := RequestUpstreamTokens(Account, CurrentRefreshToken);
  except
    on EUpstreamGrantRevoked do
    begin
      MarkNeedsReconnect(Account, Context);
      raise ELinkedAccountNeedsReconnect.Create(ReasonRevoked);
    end;
  end;

  StoreRefreshedAccount(Account, Context, CurrentRefreshToken, Tokens);

  Result.AccessToken := Tokens.AccessToken;
  Result.ExpiresAtUtc := Tokens.ExpiresAtUtc;
  StoreCachedToken(Context, Result);
end;

function TLinkedAccounts.RequestUpstreamTokens(const Account: TLinkedAccount; const RefreshToken: string): TUpstreamTokens;
begin
  var Provider: IUpstreamProvider;
  if not FProviders.TryGet(Account.Key.Provider, Provider) then
    raise EUpstreamError.Create('The upstream provider of the account is not registered');

  const GrantedScopes = Account.GrantedScopes.Split([' '], TStringSplitOptions.ExcludeEmpty);
  Result := Provider.Refresh(RefreshToken, GrantedScopes);
end;

procedure TLinkedAccounts.MarkNeedsReconnect(const Account: TLinkedAccount; const Context: string);
begin
  var Marked := Account;
  Marked.NeedsReconnect := True;
  Marked.UpdatedAtUtc := FClock.NowUtc;
  FAccounts.Save(Marked);

  RemoveCachedToken(Context);
end;

procedure TLinkedAccounts.StoreRefreshedAccount(const Account: TLinkedAccount; const Context, CurrentRefreshToken: string; const Tokens: TUpstreamTokens);
begin
  // A provider may leave out the refresh token; the current one then stays valid.
  const HasNewRefreshToken = not Tokens.RefreshToken.IsEmpty;
  const IsRewrapNeeded = FProtector.NeedsRewrap(Account.ProtectedRefreshToken);

  // The response tells which scopes the grant still has; a scope an administrator removed then shows up as missing_scopes.
  const HasChangedScopes = (not Tokens.Scope.IsEmpty and (Tokens.Scope <> Account.GrantedScopes));
  const IsStoreNeeded = (HasNewRefreshToken or IsRewrapNeeded or HasChangedScopes);
  if not IsStoreNeeded then
    Exit;

  var Updated := Account;
  if HasChangedScopes then
    Updated.GrantedScopes := Tokens.Scope;

  if HasNewRefreshToken then
  begin
    Updated.ProtectedRefreshToken := FProtector.Protect(Tokens.RefreshToken, Context);
  end
  else
  begin
    Updated.ProtectedRefreshToken := FProtector.Protect(CurrentRefreshToken, Context);
  end;
  Updated.UpdatedAtUtc := FClock.NowUtc;

  FAccounts.Save(Updated);
end;

end.
