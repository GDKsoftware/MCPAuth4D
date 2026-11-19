unit MCPAuth.Client;

interface

uses
  MCPServer.Authorization;

type
  // Entry points for an MCP server that has its tokens issued by the auth server.
  TMCPAuthClient = record
  public
    const DEFAULT_CACHE_SECONDS = 60;

    class function CreateAuthorizer(const ResourceUri, InternalBaseUrl, ServiceId, ServiceSecret: string; const CacheSeconds: Integer = DEFAULT_CACHE_SECONDS): IMCPAuthorizer; static;

    // The page where users manage their accounts; for the error messages of MCP servers.
    class function AccountPageUrl(const Issuer: string): string; static;
  end;

implementation

uses
  System.SysUtils,
  MCPAuth.Clock,
  MCPAuth.Client.Authorizer;

const
  IntrospectPath = '/internal/introspect';
  AccountPath = '/account';
  SlashChar = '/';

{ TMCPAuthClient }

class function TMCPAuthClient.CreateAuthorizer(const ResourceUri, InternalBaseUrl, ServiceId, ServiceSecret: string; const CacheSeconds: Integer): IMCPAuthorizer;
begin
  const BaseUrl = InternalBaseUrl.TrimRight([SlashChar]);

  Result := TCachingAuthorizer.Create(ResourceUri, BaseUrl + IntrospectPath, ServiceId, ServiceSecret, CacheSeconds, TSystemClock.Create);
end;

class function TMCPAuthClient.AccountPageUrl(const Issuer: string): string;
begin
  Result := Issuer.TrimRight([SlashChar]) + AccountPath;
end;

end.
