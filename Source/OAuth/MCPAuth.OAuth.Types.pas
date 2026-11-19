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

implementation

end.
