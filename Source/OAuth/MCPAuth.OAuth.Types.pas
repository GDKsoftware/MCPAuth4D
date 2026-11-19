unit MCPAuth.OAuth.Types;

interface

{$SCOPEDENUMS ON}

type
  TLoginPurpose = (Authorize, LinkAccount, Portal);
  TTokenKind = (Access, Refresh);

  TOAuthClient = record
    ClientId: string;
    ClientName: string;
    RedirectUris: TArray<string>;
    CreatedAtUtc: TDateTime;
  end;

  TPendingAuthorization = record
    Id: string;
    Purpose: TLoginPurpose;
    ClientId: string;
    RedirectUri: string;
    CodeChallenge: string;
    State: string;
    Scope: string;
    Resource: string;
    UserId: string;
    UpstreamProvider: string;
    UpstreamVerifier: string;
    BrowserBindingHash: string;          // hash of the login cookie of the browser that started the upstream sign-in
    ExpiresAtUtc: TDateTime;
  end;

  TAuthorizationGrant = record
    CodeHash: string;
    ClientId: string;
    RedirectUri: string;
    CodeChallenge: string;
    UserId: string;
    Scope: string;
    Resource: string;
    ExpiresAtUtc: TDateTime;
  end;

  TIssuedToken = record
    Hash: string;
    Kind: TTokenKind;
    FamilyId: string;
    UserId: string;
    ClientId: string;
    Scope: string;
    Resource: string;
    Consumed: Boolean;
    CreatedAtUtc: TDateTime;
    ExpiresAtUtc: TDateTime;
  end;

  TGrantedFamily = record
    FamilyId: string;
    UserId: string;
    ClientId: string;
    Resource: string;
    CreatedAtUtc: TDateTime;
  end;

  TAuthorizeRequest = record
    ResponseType: string;
    ClientId: string;
    RedirectUri: string;
    CodeChallenge: string;
    CodeChallengeMethod: string;
    State: string;
    Scope: string;
    Resource: string;
  end;

  TAuthorizeStart = record
    PendingId: string;
    UpstreamUrl: string;                 // empty when the caller already has a session
    BrowserBinding: string;              // value for the login cookie; empty when no upstream sign-in starts
  end;

  TUpstreamCallback = record
    ProviderName: string;
    State: string;
    Code: string;
    BrowserBinding: string;              // the login cookie of the calling browser; empty when it sent none
    SessionUserId: string;               // the user of the calling browser's session; empty without one
  end;

  TUpstreamCompletion = record
    Purpose: TLoginPurpose;
    UserId: string;
    PendingId: string;                   // only for Authorize: the pending entry that now waits for consent
  end;

  TConsentInfo = record
    ClientName: string;
    RedirectHost: string;
    ResourceName: string;
  end;

  TTokenRequest = record
    GrantType: string;
    Code: string;
    RedirectUri: string;
    ClientId: string;
    CodeVerifier: string;
    RefreshToken: string;
    Resource: string;
  end;

  TTokenResponse = record
    AccessToken: string;
    TokenType: string;
    ExpiresIn: Integer;
    RefreshToken: string;
    Scope: string;
  end;

implementation

end.
