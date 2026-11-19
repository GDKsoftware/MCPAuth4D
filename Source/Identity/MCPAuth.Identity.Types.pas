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

implementation

{ TAccountKey }

function TAccountKey.Value: string;
begin
  Result := Format('%s:%s:%s', [Provider, TenantId, ObjectId]).ToLowerInvariant;
end;

end.
