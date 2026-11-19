# MCPAuth4D

Central OAuth server and client for Delphi MCP servers, with linked upstream accounts.

MCPAuth4D lets several MCP servers share one OAuth 2.1 authorization server. Users sign in once with an upstream identity provider (Microsoft Entra ID out of the box), can link more upstream accounts, and give each MCP client consent per MCP server. The MCP servers run no OAuth flow of their own: they ask the central server whether a token is valid, and fetch upstream access tokens for the accounts the user linked.

## Contents

- [Architecture](#architecture)
- [Requirements](#requirements)
- [Running the auth server](#running-the-auth-server)
- [Configuration](#configuration)
- [Resource registry](#resource-registry)
- [Hooking an MCP server in](#hooking-an-mcp-server-in)
- [Templates](#templates)
- [Stores and adding a database](#stores-and-adding-a-database)
- [Units](#units)
- [Building and testing](#building-and-testing)
- [Operating system dependencies](#operating-system-dependencies)
- [License](#license)

## Architecture

```
  MCP client (an AI assistant, an IDE, ...)
        |  OAuth 2.1 + PKCE, dynamic client registration
        v
  +--------------------- reverse proxy (TLS) ----------------------+
  |  auth.example.com/*              -> 127.0.0.1:8100  (public)   |
  |  mcp.example.com/whoami/...      -> 127.0.0.1:8080  (MCP)      |
  |  /internal/*                     -> never forwarded            |
  +----------------------------------------------------------------+
        |                                     |
        v                                     v
  MCPAuthServer                          MCP server (TMCPIdHTTPServer)
    public listener   :8100                Authorizer = TMCPAuthClient.CreateAuthorizer
      /.well-known/oauth-authorization-server, /register,
      /authorize, /callback/<provider>, /consent, /token, /revoke,
      /login, /account, /logout
    internal listener 127.0.0.1:8101  <--- POST /internal/introspect
      (service id + secret, HTTP Basic)     POST /internal/accounts
                                            POST /internal/upstream-token
        |
        v
  Microsoft Entra ID (upstream sign-in; refresh tokens stored encrypted)
```

- **Two listeners.** The public listener serves the OAuth endpoints and the account pages. The internal listener serves the endpoints for MCP servers and binds to `127.0.0.1` by default. The internal routes do not exist on the public listener (they answer 404 there), so a proxy mistake cannot expose them.
- **Resource registry.** A JSON file lists every MCP server (resource) that may use the auth server: its canonical URI, its display name, its service id with the SHA-256 of its service secret, and the upstream scopes it needs. A token is issued for exactly one resource; introspection by another resource answers `active: false`.
- **Linked accounts.** Every upstream account a user signs in with or links is stored with its refresh token, encrypted with AES-256-GCM. MCP servers ask for an upstream access token per account; the auth server refreshes it when needed. When the upstream consent was revoked, or a resource needs more scopes than the account granted, the answer is `reconnect_required` and the account page shows "Reconnect".
- **Sensitive values.** Tokens, codes, session ids and service secrets are stored only as SHA-256 hashes (base64url). Logs and error messages never carry a token, code, secret, key or e-mail address.
- **Revocation delay.** An MCP server caches a positive introspection result for up to 60 seconds, so a revoked token can keep working at that MCP server for up to a minute.
- **Security notes.** [docs/security.md](docs/security.md) describes the sign-in binding, cookies, refresh-token rotation, caches, upstream scopes, cleanup and the known limits.

## Requirements

- Delphi 12.2 or newer. Developed and tested with Delphi 13 on Win64 and Linux64.
- Git submodules in `lib/`: [Delphi-MCP-Server](https://github.com/GDKsoftware/Delphi-MCP-Server), [Spring4D](https://bitbucket.org/sglienke/spring4d) and [TaurusTLS](https://github.com/JPeterMugaas/TaurusTLS).
- The libraries listed under [Operating system dependencies](#operating-system-dependencies).

Clone with submodules:

```
git clone --recurse-submodules https://github.com/GDKsoftware/MCPAuth4D.git
```

or, in an existing clone, `git submodule update --init`.

## Running the auth server

`Server/MCPAuthServer.dpr` is a ready-made console program that composes everything from environment variables. Build it with:

```
powershell -File build/build.ps1 -Project Server/MCPAuthServer.dpr -Platform Linux64 -Config Release
```

The executable lands in `bin/Linux64/Release`. Deploy it with the `templates/` folder next to it, plus `migrations/` for PostgreSQL. [docs/deployment.md](docs/deployment.md) has a systemd unit and an nginx configuration.

- `MCPAuthServer` runs until Ctrl+C (Windows) or SIGINT/SIGTERM (Linux), then stops both listeners and the maintenance thread.
- `MCPAuthServer --hash-secret` reads a service secret from standard input and prints its hash for the registry. `MCPAuthServer --hash-secret <secret>` also works, but leaves the secret in the shell history.
- Once per hour a maintenance thread deletes expired tokens and sessions.
- A configuration error stops the program at startup with a message that names the variable, never its value. The program also refuses to start when a resource in the registry uses a provider that is not configured.

The program uses `TAllowAllAccessPolicy`: every account the upstream provider accepts can sign in. With the multi-tenant Microsoft provider that is any work or school account, and each MCP server decides what a user may do. To limit sign-in, for example to some tenants, compose your own program from the library units (`MCPAuth.Server.Composition` is the template) and pass your own `IAccessPolicy` to `TLinkedAccounts`.

## Configuration

| Variable | Required / default | Meaning |
|----------|--------------------|---------|
| `MCPAUTH_ISSUER` | required | Public base URL of the auth server, for example `https://auth.example.com`. A trailing `/` is removed. Session cookies get `Secure` when it starts with `https://`. |
| `MCPAUTH_PUBLIC_PORT` | `8100` | Port of the public listener. |
| `MCPAUTH_PUBLIC_BIND` | `127.0.0.1` | Address of the public listener. Behind a reverse proxy on the same machine, keep the loopback address. |
| `MCPAUTH_INTERNAL_PORT` | `8101` | Port of the internal listener. |
| `MCPAUTH_INTERNAL_BIND` | `127.0.0.1` | Address of the internal listener. Change it only when the MCP servers run on another host of a private network. |
| `MCPAUTH_REGISTRY` | required | Path of the registry JSON, see [Resource registry](#resource-registry). |
| `MCPAUTH_STORE` | `memory` | `memory` (everything is lost on restart; for development) or `postgres`. |
| `MCPAUTH_DB` | required with `postgres` | FireDAC connection string, for example `DriverID=PG;Server=127.0.0.1;Port=5432;Database=mcpauth;User_Name=mcpauth;Password=...`. Values cannot contain `;`. |
| `MCPAUTH_MIGRATIONS` | `<exe folder>/migrations` | Folder that holds `postgres/NNNN_*.sql`. |
| `MCPAUTH_TEMPLATES` | empty | Folder with project templates that override the library templates file by file. |
| `MCPAUTH_LIBRARY_TEMPLATES` | `<exe folder>/templates` | Folder with the library templates. |
| `MCPAUTH_MICROSOFT_CLIENT_ID` | optional | Application (client) id of the Entra app registration. |
| `MCPAUTH_MICROSOFT_CERTIFICATE` | preferred credential | Path of a PEM file with the certificate and its unencrypted RSA private key. |
| `MCPAUTH_MICROSOFT_CLIENT_SECRET` | alternative credential | Client secret of the app registration. |
| `MCPAUTH_ALLOW_HTTP_RESOURCES` | `0` | `1` allows `http://` resource URIs in the registry; for local development only. |
| `MCPAUTH_MASTER_KEY` | required | Base64 of 32 random bytes; encrypts the upstream refresh tokens. |
| `MCPAUTH_MASTER_KEY_ID` | `1` | Id of the current key. |
| `MCPAUTH_PREVIOUS_KEYS` | empty | Older keys that can still decrypt: `id=base64;id=base64`. |

- The Microsoft provider is active when the client id is set together with the certificate or the secret. When both credentials are set, the certificate wins and a warning is logged.
- When the default template or migration folder does not exist next to the executable, the program searches the parent folders. A build started from `bin/<platform>/<config>` therefore uses the `templates/` and `migrations/` folders of the repository.
- Generate a master key with `openssl rand -base64 32`. To rotate it, move the current key into `MCPAUTH_PREVIOUS_KEYS`, set a new key with a new id and restart. Refresh tokens encrypted with an older key keep working.
- The listeners close a connection that sends nothing for 30 seconds and accept at most 256 connections each. PostgreSQL connections get `statement_timeout` 30 s and `lock_timeout` 10 s, unless the connection string sets its own `PGAdvanced`.

### Entra app registration

- Supported account types: accounts in any organizational directory (multi-tenant).
- Redirect URI (platform Web): `<MCPAUTH_ISSUER>/callback/microsoft`.
- Delegated Microsoft Graph permissions: the scopes your resources list in the registry. The provider adds `openid`, `profile` and `offline_access` itself.
- Credential: upload the certificate (preferred) or create a client secret.

## Resource registry

```json
{
  "resources": [
    {
      "resource": "https://mcp.example.com/whoami/mcp",
      "name": "Who am I",
      "service_id": "whoami",
      "service_secret_sha256": "<output of MCPAuthServer --hash-secret>",
      "providers": [
        { "provider": "microsoft", "scopes": ["User.Read"] }
      ]
    }
  ]
}
```

- `resource` is the canonical URI of the MCP server, exactly as clients send it in the `resource` parameter (RFC 8707) and as the MCP server publishes it in its protected-resource metadata. It must use `https` unless `MCPAUTH_ALLOW_HTTP_RESOURCES=1`.
- `name` is shown on the consent and account pages.
- `service_id` and the secret behind `service_secret_sha256` are the HTTP Basic credentials of the MCP server on the internal endpoints. Resource URIs and service ids must be unique.
- `providers` lists the upstream providers the resource needs and the scopes it needs from each. At sign-in the Microsoft provider asks for the union of the scopes of all resources; a refresh asks only for the scopes the account granted. After you add a resource with a new scope, existing accounts get `reconnect_required` (`missing_scopes`) for that resource only, until the user reconnects the account.

The registry is read at startup; restart the server after a change.

## Hooking an MCP server in

An MCP server built on [Delphi-MCP-Server](https://github.com/GDKsoftware/Delphi-MCP-Server) needs only the units in `Source/Client`, plus their dependencies in `Source/Clock` and `Source/Secret`. `Examples/WhoAmI` is a complete example.

```delphi
uses
  MCPServer.Host,
  MCPAuth.Client,
  MCPAuth.Client.UpstreamAccounts,
  MCPAuth.Client.UpstreamAccounts.Interfaces;

const
  Issuer      = 'https://auth.example.com';            // public address of the auth server
  InternalUrl = 'http://127.0.0.1:8101';               // internal listener of the auth server
  ResourceUri = 'https://mcp.example.com/whoami/mcp';  // as in the registry
  ServiceId   = 'whoami';

begin
  const Host = TMCPServerHost.Create;
  try
    Host.Settings.Port := 8080;
    Host.Settings.AuthorizationServers := Issuer;  // published in /.well-known/oauth-protected-resource
    Host.Settings.ResourceUri := ResourceUri;      // the audience tokens must carry
    Host.Authorizer := TMCPAuthClient.CreateAuthorizer(ResourceUri, InternalUrl, ServiceId, ServiceSecret);

    const Accounts: IUpstreamAccounts = TRemoteUpstreamAccounts.Create(InternalUrl, ServiceId, ServiceSecret);
    Host.AddTool(TMyTool.Create(Accounts));
    Host.StartHttp;
    // ... wait for a stop signal, then Host.Stop
  finally
    Host.Free;
  end;
end;
```

Inside a tool (`ExecuteWithContext`):

```delphi
const UserId = Context.GetPrincipal;               // the user id of the auth server
const Linked = FAccounts.ListForUser(UserId);      // the upstream accounts of this user
const GraphToken = FAccounts.GetAccessToken(UserId, Linked[0].Key);
```

- `CreateAuthorizer` returns a `TCachingAuthorizer`. It runs RFC 7662 introspection against `/internal/introspect` with the service credentials, checks that the token was issued for this resource, and caches a positive result for at most 60 seconds or until the token expires. Negative results are never cached. It subclasses `TMCPIntrospectionAuthorizer` of Delphi-MCP-Server and overrides its protected `TryValidateToken`.
- `GetAccessToken` caches the upstream token until a minute before it expires. It raises `EUpstreamAccountNotFound`, `EUpstreamAccessForbidden` (no consent for this resource) or `EUpstreamAccountNeedsReconnect` (`Reason` is `revoked` or `missing_scopes`). In that last case, point the user to `TMCPAuthClient.AccountPageUrl(Issuer)`.
- Never forward the bearer token the MCP server received to an upstream API, and never put an upstream token in a tool result.

## Templates

The pages (`login`, `consent`, `account`, `error`, `done`) are [WebStencils](https://docwiki.embarcadero.com/RADStudio/en/WebStencils) templates in `templates/`, loaded as plain files. Set `MCPAUTH_TEMPLATES` to a folder of your own to override them: a file there replaces the library file of the same name, and the other files still come from the library. To restyle every page, override only `layout.html`.

- Every page starts with `@LayoutPage layout.html`; the layout places the page at `@RenderBody`.
- The page model is `@page`: `@page.Title` and `@page.Csrf` on every page, plus `ClientName`, `ResourceName`, `RedirectHost` and `PendingId` (consent), `UserDisplayName` (account) and `Message` (error, done).
- Lists use `@foreach (var account in accounts) { ... }`, `@foreach (var grant in grants) { ... }` and `@foreach (var provider in providers) { ... }`.
- Conditions use `@if account.NeedsReconnect { ... } @else { ... }`.
- A literal `@` is written `@@`, also in CSS (`@@media`).
- WebStencils HTML-encodes every value; do not switch that off with `@\`. Keep the hidden `csrf` field of every form and the field names (`pending`, `decision`, `provider`, `key`, `family`), and load nothing from other origins. The pages are sent with `frame-ancestors 'none'` and `Referrer-Policy: no-referrer`.

## Stores and adding a database

`TStoreSet` (`MCPAuth.Store.Interfaces`) bundles the repositories: users, linked accounts, clients, pending authorizations, grants, tokens and sessions. Two implementations exist:

- `TMemoryStore.CreateSet(Clock)`: in memory, for tests and development.
- `TFireDACStore.CreateSet(Factory, Clock)`: PostgreSQL through FireDAC.

```delphi
const Driver = TFireDACPgDriver.Create;                 // keep alive as long as connections are made
const Factory: IFireDACConnectionFactory = TFireDACConnectionFactory.Create(ConnectionString);
TFireDACMigrations.Apply(Factory, 'postgres', MigrationsPath);
const Stores = TFireDACStore.CreateSet(Factory, Clock);
```

- `TFireDACConnectionFactory` registers a private, pooled FireDAC connection definition. Every repository call takes a connection from the pool and hands it back, so no connection is shared between threads.
- `TFireDACMigrations.Apply` runs `<MigrationsPath>/<dialect>/NNNN_*.sql` in order, each file in its own transaction together with its row in the version table (default `mcpauth_schema_version`). Applied files are skipped, and the version table is locked per file, so servers that start together apply each file once. An MCP server can keep its own migrations with its own `VersionTable`.
- The schema uses the prefix `mcpauth_`, `timestamptz` for times and `bytea` for bytes. Times are written with an explicit UTC offset and read back as UTC, whatever the session or machine time zone.
- Connections open with `ResourceOptions.SilentMode`, so console and service programs need no FireDAC wait-cursor unit.

To add another SQL database:

1. Add a dialect to `TSqlDialect` (`MCPAuth.Store.FireDAC.Dialect`). Upsert, `RETURNING` and the version-table statements are the only database-specific SQL in the repositories.
2. Add `migrations/<dialect>/` with the same tables as the files in `migrations/postgres/`.
3. Link the FireDAC driver of that database, and add an overload of `TFireDACStore.CreateSet` that takes the dialect.
4. Run the contract tests against it: derive a fixture from `TStoreContractTests`, as `MCPAuth.Store.FireDAC.Tests` does.

A store that is not SQL implements the interfaces in `MCPAuth.Store.Interfaces`, `MCPAuth.Identity.Interfaces` and `MCPAuth.OAuth.Interfaces`, and passes the same contract tests.

## Units

| Module | Unit | Purpose |
|--------|------|---------|
| Secret | `MCPAuth.Secret.Interfaces` | `ITokenGenerator`, `IKeyRing`, `ISecretProtector` and the secret exceptions |
| | `MCPAuth.Secret.Token` | Random tokens: 32 bytes from OpenSSL, base64url |
| | `MCPAuth.Secret.Hash` | `TTokenHash`: SHA-256 as base64url, and a constant-time comparison |
| | `MCPAuth.Secret.KeyRing` | Master key and previous keys, read from environment variables |
| | `MCPAuth.Secret.AesGcm` | AES-256-GCM envelopes with key ids, for key rotation |
| | `MCPAuth.Secret.OpenSsl` | Loads OpenSSL 3 through TaurusTLS |
| Clock | `MCPAuth.Clock.Interfaces`, `MCPAuth.Clock` | `IClock` (UTC) and the system clock |
| Identity | `MCPAuth.Identity.Types`, `.Interfaces`, `.Exceptions` | Users, linked accounts and `ILinkedAccounts` |
| | `MCPAuth.Identity.Accounts` | Sign-in, linking, encrypted refresh tokens, upstream token refresh |
| | `MCPAuth.Identity.Access.Interfaces`, `.Access.AllowAll` | `IAccessPolicy` and the allow-all policy |
| Resource | `MCPAuth.Resource.Types`, `.Interfaces`, `.Exceptions` | Resource definitions and `IResourceRegistry` |
| | `MCPAuth.Resource.Registry.Json` | The registry from a JSON file |
| | `MCPAuth.Resource.ServiceAuth` | HTTP Basic service authentication and `HashSecret` |
| OAuth | `MCPAuth.OAuth.Types`, `.Interfaces`, `.Errors`, `.Settings` | OAuth types, store interfaces, `EOAuthError` and settings |
| | `MCPAuth.OAuth.Pkce`, `.RedirectPolicy` | PKCE S256 and the redirect URI rules |
| | `MCPAuth.OAuth.Metadata`, `.Registration` | RFC 8414 metadata and RFC 7591 client registration |
| | `MCPAuth.OAuth.Server` | `TAuthorizationServer`: authorize, consent, tokens, refresh rotation, revocation |
| Upstream | `MCPAuth.Upstream.Types`, `.Interfaces`, `.Exceptions` | Upstream identities, tokens and providers |
| | `MCPAuth.Upstream.Http.Interfaces`, `.Http`, `.FormEncoding` | Form posts to token endpoints with `THTTPClient` |
| | `MCPAuth.Upstream.Jwt` | Reads ID token claims |
| | `MCPAuth.Upstream.OAuth` | Generic OAuth 2.0 authorization-code provider with PKCE |
| | `MCPAuth.Upstream.Credential.Secret`, `.Credential.Certificate` | Client secret, and certificate (RFC 7523 client assertion) |
| | `MCPAuth.Upstream.Microsoft` | Microsoft Entra ID, multi-tenant; the only unit that knows Microsoft endpoints |
| | `MCPAuth.Upstream.Providers` | The set of configured providers |
| Store | `MCPAuth.Store.Interfaces` | `TStoreSet` and the session store |
| | `MCPAuth.Store.Memory`, `MCPAuth.Store.Memory.<Repository>` | In-memory store |
| | `MCPAuth.Store.FireDAC`, `MCPAuth.Store.FireDAC.<Repository>` | PostgreSQL store |
| | `MCPAuth.Store.FireDAC.Interfaces`, `.ConnectionFactory`, `.PgDriver`, `.Command`, `.Dialect`, `.Exceptions` | Connections, driver, statements and dialect |
| | `MCPAuth.Store.FireDAC.Migrations` | Versioned SQL migrations |
| Web | `MCPAuth.Web.Types`, `.Router` | Request, response and router, independent of Indy |
| | `MCPAuth.Web.Session.Interfaces`, `.Session`, `.Cookie`, `.LoginBinding` | Session cookies, CSRF and the login cookie that binds an upstream sign-in to its browser |
| | `MCPAuth.Web.Page.Interfaces`, `.Page.Models`, `.Page.WebStencils`, `.Page.Exceptions` | Page models and the WebStencils renderer |
| | `MCPAuth.Web.Controller.OAuth`, `.Controller.Account` | Public OAuth endpoints and the account pages |
| | `MCPAuth.Web.Server.Indy` | `TMCPAuthWebServer`: one router on one Indy listener |
| | `MCPAuth.Web.ErrorLog` | Logs unexpected exceptions without request details |
| Internal | `MCPAuth.Internal.Controller` | `/internal/introspect`, `/internal/accounts` and `/internal/upstream-token` |
| Client | `MCPAuth.Client` | `TMCPAuthClient.CreateAuthorizer` and `AccountPageUrl` |
| | `MCPAuth.Client.Authorizer` | `TCachingAuthorizer` |
| | `MCPAuth.Client.UpstreamAccounts.Interfaces`, `.UpstreamAccounts`, `.UpstreamAccounts.Exceptions` | `IUpstreamAccounts` over the internal endpoints |
| Server | `MCPAuth.Server.Settings`, `.Exceptions` | Settings from the `MCPAUTH_*` variables |
| | `MCPAuth.Server.Composition` | Composition root of the auth server program |
| | `MCPAuth.Server.Maintenance` | Hourly deletion of expired tokens and sessions |
| | `MCPAuth.Server.Shutdown`, `.CommandLine` | Stop signals and the command line of `MCPAuthServer` |

## Building and testing

There is no CI: the tests run locally. The scripts call the command-line compilers directly, so no `.dproj` is needed.

```
powershell -File build/test.ps1 -Platform Win64
powershell -File build/test.ps1 -Platform Linux64
```

`build/test.ps1` builds `Tests/MCPAuth.Tests.dpr` and runs it. It exits non-zero when the build fails, when the compiler reports a hint or warning in this repository's own code, or when a test fails. `build/build.ps1 -Project <path.dpr> -Platform Win64|Linux64 -Config Debug|Release` builds any program of the repository, such as `Server/MCPAuthServer.dpr` or `Examples/WhoAmI/WhoAmIServer.dpr`; the output goes to `bin/<Platform>/<Config>`.

Machine settings live in `build/env.ps1`. Copy `build/env.local.example.ps1` to `build/env.local.ps1` to override them:

- `BDS_ROOT`, `BDS_COMMON`: the Delphi installation (default Delphi 13, `Studio\37.0`).
- `LINUX_SDK_ROOT`: the Linux64 SDK imported in the IDE (default `ubuntu26.04.sdk`).
- `WSL_DISTRO`: the WSL distribution that runs the Linux64 tests (default `Ubuntu`).
- `OPENSSL_DIR`: folder with `libcrypto-3-x64.dll` and `libssl-3-x64.dll`.
- `PG_BIN_DIR`: folder with `libpq.dll` for the Win64 PostgreSQL store tests.

The Linux64 tests run inside WSL.

### PostgreSQL store tests

The FireDAC store runs the same contract tests as the in-memory store, plus migration tests. They need a PostgreSQL database and only run when `MCPAUTH_TEST_PG` holds a FireDAC connection string; without it they pass without touching a database.

`build/docker-compose.yml` starts PostgreSQL 17 on port 55432 with test-only credentials. With Docker inside WSL:

```
wsl -d Ubuntu -- docker compose -f /mnt/c/<path-to-repo>/build/docker-compose.yml up -d --wait
$env:MCPAUTH_TEST_PG = 'DriverID=PG;Server=127.0.0.1;Port=55432;Database=mcpauth_test;User_Name=mcpauth_test;Password=mcpauth_test'
powershell -File build/test.ps1 -Platform Win64
powershell -File build/test.ps1 -Platform Linux64
```

WSL2 forwards the port to `127.0.0.1` on Windows. When forwarding does not work, use the address from `wsl hostname -I` as `Server`. WSL stops an idle distribution after a while, and the container with it; run `docker compose up -d` again when the tests cannot connect.

The tests drop and recreate the `mcpauth_` tables of that database: never point `MCPAUTH_TEST_PG` at a database with data you want to keep. `build/test.ps1` passes `MCPAUTH_TEST_PG` and `MCPAUTH_PG_VENDORLIB` (another libpq file to load, if needed) on to WSL.

### Trying it locally

The auth server with the memory store and the WhoAmI example run together on one machine; see [Examples/WhoAmI/README.md](Examples/WhoAmI/README.md).

## Operating system dependencies

| Library | Used by | Win64 | Linux64 |
|---------|---------|-------|---------|
| OpenSSL 3 (`libcrypto`, `libssl`) | Tokens, hashing, AES-GCM and the certificate credential, through TaurusTLS | `libcrypto-3-x64.dll` and `libssl-3-x64.dll` next to the executable or on the `PATH`. After a Win64 build, `build/build.ps1` copies them from `OPENSSL_DIR`, `C:\Program Files\OpenSSL-Win64\bin`, or the `mingw64\bin` or `ucrt64\bin` folder of Git for Windows. | `libcrypto.so.3` and `libssl.so.3` (package `libssl3`, installed by default on Ubuntu). |
| libpq | The PostgreSQL store (FireDAC PG driver) | `libpq.dll` and the DLLs it depends on, on the `PATH`: the `bin` folder of a PostgreSQL installation or of the official Windows binaries zip. | `libpq.so.5` (`sudo apt-get install -y libpq5`). |
| libcurl | `THTTPClient`: upstream token requests and the client side of MCP servers | Nothing to install; Windows uses WinHTTP. | `libcurl.so.4` (`sudo apt-get install -y libcurl4`). |

## License

MIT, see [LICENSE](LICENSE).
