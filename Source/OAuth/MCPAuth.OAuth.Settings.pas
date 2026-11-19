unit MCPAuth.OAuth.Settings;

interface

type
  TMCPAuthSettings = record
    Issuer: string;
    Scope: string;
    AccessTokenSeconds: Integer;
    RefreshTokenDays: Integer;
    CodeSeconds: Integer;
    PendingSeconds: Integer;
    SessionHours: Integer;
    ExtraRedirectUris: TArray<string>;
    ProjectTemplatesPath: string;
    LibraryTemplatesPath: string;
    SecureCookies: Boolean;
    IntrospectionCacheSeconds: Integer;

    class function Defaults(const Issuer: string): TMCPAuthSettings; static;
  end;

implementation

{ TMCPAuthSettings }

class function TMCPAuthSettings.Defaults(const Issuer: string): TMCPAuthSettings;
begin
  Result := Default(TMCPAuthSettings);
  Result.Issuer                    := Issuer;
  Result.Scope                     := 'mcp';
  Result.AccessTokenSeconds        := 3600;
  Result.RefreshTokenDays          := 30;
  Result.CodeSeconds               := 300;
  Result.PendingSeconds            := 600;
  Result.SessionHours              := 12;
  Result.SecureCookies             := True;
  Result.IntrospectionCacheSeconds := 60;
end;

end.
