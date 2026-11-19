unit MCPAuth.OAuth.Interfaces;

interface

uses
  Spring.Collections,
  MCPAuth.OAuth.Types;

type
  IClientRepository = interface
    ['{2D8B6F13-A4C9-4075-B1E2-9F30C7A5D864}']
    function TryGet(const ClientId: string; out Client: TOAuthClient): Boolean;
    procedure Save(const Client: TOAuthClient);
  end;

  IPendingAuthorizationStore = interface
    ['{91E4A7C0-5B2D-48F6-83A1-D6C0E2B97F35}']
    procedure Put(const Pending: TPendingAuthorization);

    // An expired entry counts as absent.
    function TryGet(const Id: string; out Pending: TPendingAuthorization): Boolean;
    function TryTake(const Id: string; out Pending: TPendingAuthorization): Boolean;
  end;

  IGrantStore = interface
    ['{4F60B9D2-E87A-4C13-A5D0-18B3C7E9F246}']
    procedure Put(const Grant: TAuthorizationGrant);
    function TryTake(const CodeHash: string; out Grant: TAuthorizationGrant): Boolean;
  end;

  ITokenRepository = interface
    ['{A8C35E71-0D94-4B2F-9E68-3B1F7D5A0C82}']
    // An expired token counts as absent.
    function TryGet(const Hash: string; out Token: TIssuedToken): Boolean;
    procedure Save(const Token: TIssuedToken);

    // Atomic: True only when the token existed, was not yet Consumed and not expired.
    function TryConsume(const Hash: string; out Token: TIssuedToken): Boolean;

    // Detects reuse of a rotated refresh token.
    function IsKnownConsumed(const Hash: string; out FamilyId: string): Boolean;
    procedure DeleteFamily(const FamilyId: string);
    procedure DeleteForUser(const UserId: string);
    function ListFamiliesForUser(const UserId: string): IReadOnlyList<TGrantedFamily>;
    function HasActiveFamily(const UserId, Resource: string): Boolean;
    function DeleteExpired(const NowUtc: TDateTime): Integer;
  end;

  // Every failure raises EOAuthError. During authorize, invalid_client and invalid_redirect_uri
  // must be shown as an error page and never be redirected to the client.
  IAuthorizationServer = interface
    ['{C5A1E847-2F6B-4D93-8B0C-7E4D19A3F562}']
    function BeginAuthorize(const Request: TAuthorizeRequest): TAuthorizeStart; overload;
    function BeginAuthorize(const Request: TAuthorizeRequest; const SessionUserId: string): TAuthorizeStart; overload;

    function BeginLogin(const ProviderName: string; const Purpose: TLoginPurpose; const UserId: string = ''): string;

    // Also raises EUpstreamError from the provider and EAccessDenied or EAccountLinkedToOtherUser from the linked accounts.
    function CompleteUpstream(const ProviderName, State, Code: string): TUpstreamCompletion;

    function ConsentInfo(const PendingId: string): TConsentInfo;

    // Only the user who signed in for this pending authorization may approve it.
    function Approve(const PendingId, UserId: string): string;
    function Deny(const PendingId: string): string;

    function ExchangeToken(const Request: TTokenRequest): TTokenResponse;

    // Revokes the whole family of the token; an unknown token is ignored.
    procedure Revoke(const Token: string);

    // A family of another user is ignored.
    procedure RevokeFamily(const UserId, FamilyId: string);
  end;

implementation

end.
