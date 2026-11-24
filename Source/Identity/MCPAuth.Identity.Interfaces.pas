unit MCPAuth.Identity.Interfaces;

interface

uses
  Spring.Collections,
  MCPAuth.Identity.Types,
  MCPAuth.Upstream.Types;

type
  IUserRepository = interface
    ['{0E7A4C21-8B35-4D96-A1F0-52C9D3B6E847}']
    function TryGet(const UserId: string; out User: TAuthUser): Boolean;
    procedure Save(const User: TAuthUser);
    procedure Delete(const UserId: string);
  end;

  ILoginIdentityRepository = interface
    ['{5B9E2D47-1C83-4A6F-B0E5-8D3F72A1C946}']
    function TryFind(const Key: TAccountKey; out Identity: TLoginIdentity): Boolean;
    // Ordered by CreatedAtUtc.
    function ListForUser(const UserId: string): IReadOnlyList<TLoginIdentity>;

    // Inserts or updates. Raises ELoginIdentityTaken when the key is the login identity of another user.
    procedure Save(const Identity: TLoginIdentity);
  end;

  ILinkedAccountRepository = interface
    ['{C3F18A5D-62B7-4E09-9A4C-7D1E5B8F2A60}']
    // One upstream account can be linked by several users; each has a row of his own.
    function TryFind(const UserId: string; const Key: TAccountKey; out Account: TLinkedAccount): Boolean;
    function ListForUser(const UserId: string): IReadOnlyList<TLinkedAccount>;

    // Inserts or updates the row of Account.UserId and Account.Key.
    procedure Save(const Account: TLinkedAccount);
    procedure Delete(const UserId: string; const Key: TAccountKey);
  end;

  // Both methods raise EAccessDenied when the access policy rejects the upstream identity.
  // Upstream refresh tokens are stored encrypted with the context UserId + '|' + Key.Value.
  ILinkedAccounts = interface
    ['{8E3B6A19-D27C-4F05-A4B8-C91E5D0F7362}']
    // Signs in with a login identity only: a known identity yields its user, any other account creates a new user with
    // that account as identity. Either way the account is stored as a linked account of the user, with the new refresh token.
    function ResolveOrCreateUser(const Tokens: TUpstreamTokens): TAuthUser;

    // Links the account for this user, also when other users linked it too; each user keeps a refresh token of his own.
    function Link(const UserId: string; const Tokens: TUpstreamTokens): TLinkedAccount;

    function ListForUser(const UserId: string): IReadOnlyList<TLinkedAccount>;

    // Raises ELinkedAccountNotFound for an unknown account or one of another user.
    // Raises ELinkedAccountNeedsReconnect (reason 'revoked' or 'missing_scopes') when the account has to be linked again.
    // The scopes openid, profile, offline_access and email are not checked against the granted scopes.
    function GetAccessToken(const UserId: string; const Key: TAccountKey; const RequiredScopes: TArray<string>): TUpstreamAccessToken;

    // Raises ELinkedAccountNotFound for an unknown account or one of another user.
    procedure Unlink(const UserId: string; const Key: TAccountKey);
  end;

implementation

end.
