unit MCPAuth.Identity.Types;

interface

uses
  System.SysUtils;

type
  TAccountKey = record
    Provider: string;
    TenantId: string;
    ObjectId: string;

    function Value: string;
  end;

  TAuthUser = record
    Id: string;
    DisplayName: string;
    CreatedAtUtc: TDateTime;
  end;

  TLinkedAccount = record
    Key: TAccountKey;
    UserId: string;
    DisplayName: string;
    UserName: string;
    GrantedScopes: string;
    ProtectedRefreshToken: TBytes;
    NeedsReconnect: Boolean;
    LinkedAtUtc: TDateTime;
    UpdatedAtUtc: TDateTime;
  end;

  // The upstream account a user signs in with. Linked accounts only give upstream access; they never sign anyone in.
  TLoginIdentity = record
    Key: TAccountKey;
    UserId: string;
    UserName: string;
    CreatedAtUtc: TDateTime;
    LastLoginAtUtc: TDateTime;
  end;

implementation

{ TAccountKey }

function TAccountKey.Value: string;
begin
  Result := Format('%s:%s:%s', [Provider, TenantId, ObjectId]).ToLowerInvariant;
end;

end.
