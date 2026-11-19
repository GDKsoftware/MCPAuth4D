# Deployment

This guide runs the auth server and one MCP server on a single Linux host behind nginx. The host names `auth.example.com` and `mcp.example.com` are placeholders.

## Layout on the host

```
/opt/mcpauth/
  MCPAuthServer              Linux64 Release build of Server/MCPAuthServer.dpr
  templates/                 copy of the repository's templates/
  migrations/postgres/       copy of the repository's migrations/postgres/
/etc/mcpauth/
  registry.json              the resource registry (readable by the service user only)
  mcpauth.env                environment file with the settings and secrets (mode 0600)
  microsoft.pem              certificate and private key of the Entra app (mode 0600)
```

Install the runtime libraries:

```
sudo apt-get install -y libssl3 libcurl4 libpq5
```

Create a service user without a login shell:

```
sudo useradd --system --home /opt/mcpauth --shell /usr/sbin/nologin mcpauth
sudo chown -R root:mcpauth /etc/mcpauth && sudo chmod 0750 /etc/mcpauth && sudo chmod 0640 /etc/mcpauth/*
```

## Database

Create a PostgreSQL database and a user that owns it. The server applies the migrations itself at every start; a file that was applied before is skipped.

```
CREATE USER mcpauth WITH PASSWORD '...';
CREATE DATABASE mcpauth OWNER mcpauth;
```

## Settings

`/etc/mcpauth/mcpauth.env`:

```
MCPAUTH_ISSUER=https://auth.example.com
MCPAUTH_REGISTRY=/etc/mcpauth/registry.json
MCPAUTH_STORE=postgres
MCPAUTH_DB=DriverID=PG;Server=127.0.0.1;Port=5432;Database=mcpauth;User_Name=mcpauth;Password=...
MCPAUTH_MICROSOFT_CLIENT_ID=<application id of the Entra app>
MCPAUTH_MICROSOFT_CERTIFICATE=/etc/mcpauth/microsoft.pem
MCPAUTH_MASTER_KEY=<openssl rand -base64 32>
MCPAUTH_MASTER_KEY_ID=1
```

The ports default to 8100 (public) and 8101 (internal), both on `127.0.0.1`. The README lists every variable.

Keep a copy of the master key in a password manager. Without it, the stored refresh tokens cannot be decrypted and every user has to link their accounts again.

## Registry

Generate a service secret per MCP server, give the secret to that MCP server, and put only its hash in the registry:

```
openssl rand -base64 32 | tee /dev/stderr | /opt/mcpauth/MCPAuthServer --hash-secret
```

```json
{
  "resources": [
    {
      "resource": "https://mcp.example.com/whoami/mcp",
      "name": "Who am I",
      "service_id": "whoami",
      "service_secret_sha256": "<hash>",
      "providers": [ { "provider": "microsoft", "scopes": ["User.Read"] } ]
    }
  ]
}
```

The `resource` value must be exactly the URI clients use for the MCP server, including the path. Restart the auth server after changing the registry.

## systemd

`/etc/systemd/system/mcpauth.service`:

```
[Unit]
Description=MCPAuth authorization server
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=mcpauth
Group=mcpauth
WorkingDirectory=/opt/mcpauth
EnvironmentFile=/etc/mcpauth/mcpauth.env
ExecStart=/opt/mcpauth/MCPAuthServer
Restart=on-failure
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=15
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/opt/mcpauth /etc/mcpauth

[Install]
WantedBy=multi-user.target
```

```
sudo systemctl daemon-reload
sudo systemctl enable --now mcpauth
journalctl -u mcpauth -f
```

The server logs to standard output, so the journal holds its log. SIGTERM stops both listeners and the maintenance thread before the process exits.

An MCP server gets a unit of its own in the same way, with its service secret in its own environment file and `After=mcpauth.service`.

## nginx

The public listener goes behind TLS; the internal listener is never proxied. MCP servers on the same host call `http://127.0.0.1:8101` directly.

```
server {
    listen 443 ssl;
    server_name auth.example.com;

    ssl_certificate     /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;

    # The internal endpoints live on another listener; refuse the path here as well.
    location /internal/ {
        return 404;
    }

    location / {
        proxy_pass http://127.0.0.1:8100;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        client_max_body_size 1m;
        proxy_read_timeout 30s;
    }
}

server {
    listen 443 ssl;
    server_name mcp.example.com;

    ssl_certificate     /etc/letsencrypt/live/mcp.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mcp.example.com/privkey.pem;

    # Protected-resource metadata of the MCP server whose ResourceUri is https://mcp.example.com/whoami/mcp.
    location = /.well-known/oauth-protected-resource/whoami/mcp {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
    }

    location /whoami/ {
        proxy_pass http://127.0.0.1:8080/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        proxy_read_timeout 300s;
    }
}
```

- The MCP server sets `ResourceUri` to its public URI (`https://mcp.example.com/whoami/mcp`), `AuthorizationServers` to the issuer, and `AllowedHosts` to its public host name. Delphi-MCP-Server derives the `resource_metadata` URL in its 401 challenge from `ResourceUri` and answers that metadata path itself.
- `proxy_buffering off` keeps streamed MCP responses flowing.
- With several MCP servers, add a `location` pair per server and an entry per server in the registry.

## Checks after deployment

```
curl -s https://auth.example.com/.well-known/oauth-authorization-server     # 200, issuer is https://auth.example.com
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://auth.example.com/internal/introspect   # 404
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8101/internal/introspect      # 401 (no service credentials)
curl -s -D - -o /dev/null -X POST https://mcp.example.com/whoami/mcp        # 401 with WWW-Authenticate resource_metadata
```

Then add the MCP server to an MCP client, sign in, and approve the consent page.
