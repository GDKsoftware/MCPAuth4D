unit MCPAuth.Identity.Types;

interface

uses
  System.SysUtils;

const
  AccountKeySeparator = ':';

type
  // Value is '<provider>:<tenant id>:<object id>'. The provider name and the tenant id never contain ':' and are compared
  // case-insensitively. The object id may contain anything and keeps its case, except a GUID, which is compared case-insensitively.
  TAccountKey = record
  private
    function ComparableObjectId: string;

  public
    Provider: string;
    TenantId: string;
    ObjectId: string;

    // Splits on the first two separators only, so an object id with ':' comes back whole.
    class function TryParse(const Value: string; out Key: TAccountKey): Boolean; static;

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

uses
  System.RegularExpressions;

const
  GuidPattern = '\A[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\z';

{ TAccountKey }

class function TAccountKey.TryParse(const Value: string; out Key: TAccountKey): Boolean;
begin
  Key := Default(TAccountKey);

  const FirstSeparator = Value.IndexOf(AccountKeySeparator);
  const SecondSeparator = Value.IndexOf(AccountKeySeparator, FirstSeparator + 1);
  Result := (SecondSeparator > FirstSeparator);
  if Result then
  begin
    Key.Provider := Value.Substring(0, FirstSeparator);
    Key.TenantId := Value.Substring(FirstSeparator + 1, SecondSeparator - FirstSeparator - 1);
    Key.ObjectId := Value.Substring(SecondSeparator + 1);
  end;
end;

function TAccountKey.Value: string;
begin
  Result := string.Join(AccountKeySeparator, [Provider.ToLowerInvariant, TenantId.ToLowerInvariant, ComparableObjectId]);
end;

function TAccountKey.ComparableObjectId: string;
begin
  const IsGuid = TRegEx.IsMatch(ObjectId, GuidPattern);
  if IsGuid then
  begin
    Result := ObjectId.ToLowerInvariant;
  end
  else
  begin
    Result := ObjectId;
  end;
end;

end.
