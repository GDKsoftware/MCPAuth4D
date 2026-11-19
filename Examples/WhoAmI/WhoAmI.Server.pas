unit WhoAmI.Server;

interface

type
  // Runs the WhoAmI example: an MCP server on http://localhost:8080/mcp whose tokens come from the
  // central auth server. Settings come from the environment:
  //   WHOAMI_SERVICE_SECRET  required; the secret whose hash is in the registry of the auth server
  //   WHOAMI_SERVICE_ID      default 'whoami'
  //   WHOAMI_ISSUER          default 'http://localhost:8100' (the public address of the auth server)
  //   WHOAMI_INTERNAL_URL    default 'http://127.0.0.1:8101' (the internal listener of the auth server)
  //   WHOAMI_RESOURCE        default 'http://localhost:8080/mcp' (must match the registry entry)
  //   WHOAMI_PORT            default 8080
  TWhoAmIServer = class
  private
    class function ReadVariable(const Name, DefaultValue: string): string; static;
    class procedure Serve; static;

  public
    class function Run: Integer; static;
  end;

implementation

uses
  System.SysUtils,
  MCPServer.Logger,
  MCPServer.Settings,
  MCPServer.Host,
  MCPAuth.Client,
  MCPAuth.Client.UpstreamAccounts,
  MCPAuth.Server.Shutdown,
  WhoAmI.Tool;

const
  ExitSuccess = 0;
  ExitFailed = 1;
  McpEndpoint = '/mcp';
  LocalHost = 'localhost';

resourcestring
  MissingSecret = 'Set WHOAMI_SERVICE_SECRET to the service secret of the whoami resource';
  StartedFormat = 'WhoAmI MCP server on %s, tokens from %s';
  FailedFormat = 'WhoAmI failed: %s: %s';

{ TWhoAmIServer }

class function TWhoAmIServer.Run: Integer;
begin
  TLogger.LogToConsole := True;
  try
    Serve;
    Result := ExitSuccess;
  except
    on E: Exception do
    begin
      TLogger.Error(FailedFormat, [E.ClassName, E.Message]);
      Result := ExitFailed;
    end;
  end;
end;

class function TWhoAmIServer.ReadVariable(const Name, DefaultValue: string): string;
begin
  Result := GetEnvironmentVariable(Name).Trim;
  if Result.IsEmpty then
    Result := DefaultValue;
end;

class procedure TWhoAmIServer.Serve;
begin
  const ServiceSecret = ReadVariable('WHOAMI_SERVICE_SECRET', '');
  if ServiceSecret.IsEmpty then
    raise EArgumentException.Create(MissingSecret);

  const ServiceId = ReadVariable('WHOAMI_SERVICE_ID', 'whoami');
  const Issuer = ReadVariable('WHOAMI_ISSUER', 'http://localhost:8100');
  const InternalUrl = ReadVariable('WHOAMI_INTERNAL_URL', 'http://127.0.0.1:8101');
  const ResourceUri = ReadVariable('WHOAMI_RESOURCE', 'http://localhost:8080/mcp');
  const Port = StrToInt(ReadVariable('WHOAMI_PORT', '8080'));

  const Host = TMCPServerHost.Create;
  try
    Host.Settings.Host := LocalHost;
    Host.Settings.Port := Port;
    Host.Settings.Endpoint := McpEndpoint;
    Host.Settings.ServerName := 'whoami';
    Host.Settings.AuthorizationServers := Issuer;
    Host.Settings.ResourceUri := ResourceUri;
    Host.Authorizer := TMCPAuthClient.CreateAuthorizer(ResourceUri, InternalUrl, ServiceId, ServiceSecret);

    const Accounts = TRemoteUpstreamAccounts.Create(InternalUrl, ServiceId, ServiceSecret);
    Host.AddTool(TWhoAmITool.Create(Accounts, TMCPAuthClient.AccountPageUrl(Issuer)));

    Host.StartHttp;
    TLogger.Info(StartedFormat, [ResourceUri, Issuer]);

    TShutdownSignal.WaitForSignal;
    Host.Stop;
  finally
    Host.Free;
  end;
end;

end.
