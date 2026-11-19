# WhoAmI example

A minimal MCP server that gets its tokens from the MCPAuth4D auth server. It has one tool, `whoami`, which returns:

- `user_id`: the user id of the auth server (the subject of the access token);
- `accounts`: the upstream accounts the user linked;
- `first_account_token`: whether an upstream access token could be fetched for the first account, with only its length (never the token);
- `account_page`: where the user manages the linked accounts.

`WhoAmI.Server.pas` shows the wiring: `TMCPServerHost` from Delphi-MCP-Server, with `Authorizer := TMCPAuthClient.CreateAuthorizer(...)`, `AuthorizationServers` set to the issuer, and the tool registered explicitly with `Host.AddTool`.

## Settings

| Variable | Default | Meaning |
|----------|---------|---------|
| `WHOAMI_SERVICE_SECRET` | required | The service secret whose hash is in the registry of the auth server. |
| `WHOAMI_SERVICE_ID` | `whoami` | The service id in the registry. |
| `WHOAMI_ISSUER` | `http://localhost:8100` | Public address of the auth server. |
| `WHOAMI_INTERNAL_URL` | `http://127.0.0.1:8101` | Internal listener of the auth server. |
| `WHOAMI_RESOURCE` | `http://localhost:8080/mcp` | Resource URI; must match the registry entry. |
| `WHOAMI_PORT` | `8080` | Port of the MCP server. |

## Running it locally

Build both programs:

```
powershell -File build/build.ps1 -Project Server/MCPAuthServer.dpr -Config Release
powershell -File build/build.ps1 -Project Examples/WhoAmI/WhoAmIServer.dpr -Config Release
```

Make a service secret and a registry (Git Bash or Linux shell):

```
SECRET=$(openssl rand -hex 24)
HASH=$(echo "$SECRET" | bin/Win64/Release/MCPAuthServer --hash-secret)
cat > registry.json <<EOF
{"resources":[{"resource":"http://localhost:8080/mcp","name":"Who am I","service_id":"whoami",
  "service_secret_sha256":"$HASH","providers":[{"provider":"microsoft","scopes":["User.Read"]}]}]}
EOF
```

Start the auth server with the memory store. Local `http` resources need `MCPAUTH_ALLOW_HTTP_RESOURCES=1`. The Entra app needs `http://localhost:8100/callback/microsoft` as a redirect URI.

```
export MCPAUTH_ISSUER=http://localhost:8100
export MCPAUTH_REGISTRY=$PWD/registry.json
export MCPAUTH_MASTER_KEY=$(openssl rand -base64 32)
export MCPAUTH_MICROSOFT_CLIENT_ID=<application id>
export MCPAUTH_MICROSOFT_CLIENT_SECRET=<client secret>
export MCPAUTH_ALLOW_HTTP_RESOURCES=1
bin/Win64/Release/MCPAuthServer &
```

Start WhoAmI:

```
WHOAMI_SERVICE_SECRET=$SECRET bin/Win64/Release/WhoAmIServer &
```

Quick checks:

```
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8100/.well-known/oauth-authorization-server   # 200
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8101/internal/introspect             # 401
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8100/internal/introspect             # 404
curl -s -D - -o /dev/null -X POST http://localhost:8080/mcp     # 401, WWW-Authenticate with resource_metadata
curl -s http://localhost:8080/.well-known/oauth-protected-resource/mcp   # authorization_servers = the issuer
```

Then add the server to an MCP client, for example `claude mcp add --transport http whoami http://localhost:8080/mcp`, sign in, approve the consent page and call `whoami`. Link a second account on `http://localhost:8100/account` and call `whoami` again: it lists both accounts.
