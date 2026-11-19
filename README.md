# MCPAuth4D

Central OAuth server and client for Delphi MCP servers, with linked upstream accounts.

MCPAuth4D lets several MCP servers share one OAuth authorization server. Users sign in once, link their upstream accounts, and every connected MCP server asks the central server for tokens instead of running its own OAuth flow.

The library is under construction. This first part contains the secret primitives the rest of the library builds on:

| Unit | Purpose |
|------|---------|
| `MCPAuth.Secret.Interfaces` | `ITokenGenerator`, `IKeyRing`, `ISecretProtector` and the secret exceptions |
| `MCPAuth.Secret.Token` | Random tokens: 32 bytes from OpenSSL `RAND_bytes`, base64url without padding |
| `MCPAuth.Secret.Hash` | `TTokenHash`: SHA-256 of a token as base64url, and a constant-time comparison |
| `MCPAuth.Secret.KeyRing` | Master key and previous keys for encryption, read from environment variables |
| `MCPAuth.Secret.AesGcm` | `ISecretProtector` with AES-256-GCM, key rotation through key ids |
| `MCPAuth.Secret.OpenSsl` | Loads the OpenSSL 3 libraries through TaurusTLS |

## Requirements

- Delphi 12.2 or newer. Developed and tested with Delphi 13 on Win64 and Linux64.
- OpenSSL 3 at runtime (`libcrypto` and `libssl`), loaded through [TaurusTLS](https://github.com/JPeterMugaas/TaurusTLS).
- Git submodules in `lib/`: [Delphi-MCP-Server](https://github.com/GDKsoftware/Delphi-MCP-Server), [Spring4D](https://bitbucket.org/sglienke/spring4d) and TaurusTLS.

Clone with submodules:

```
git clone --recurse-submodules https://github.com/GDKsoftware/MCPAuth4D.git
```

or, in an existing clone, `git submodule update --init`.

## Key configuration

`TKeyRing.FromEnvironment('<PREFIX>')` reads:

| Variable | Meaning |
|----------|---------|
| `<PREFIX>_MASTER_KEY` | Current key: base64 of 32 random bytes. Required. |
| `<PREFIX>_MASTER_KEY_ID` | Id of the current key. Defaults to `1`. |
| `<PREFIX>_PREVIOUS_KEYS` | Older keys that can still decrypt: `id=base64;id=base64`. Optional. |

To rotate, move the current key into `<PREFIX>_PREVIOUS_KEYS`, set a new master key with a new id, and rewrap every envelope for which `ISecretProtector.NeedsRewrap` returns `True`.

A protected value is an envelope of version byte `1`, key id length, key id, a 12-byte nonce, the ciphertext and a 16-byte tag. The context passed to `Protect` and `Unprotect` is authenticated but not stored, so an envelope only decrypts with the same context.

## Building and testing

There is no CI: the tests run locally. The scripts call the command-line compilers directly, so no `.dproj` is needed.

```
powershell -File build/test.ps1 -Platform Win64
powershell -File build/test.ps1 -Platform Linux64
```

`build/test.ps1` builds `Tests/MCPAuth.Tests.dpr` and runs it. It exits non-zero when the build fails, when the compiler reports a hint or warning in this repository's own code, or when a test fails. `build/build.ps1 -Project <path.dpr> -Platform Win64|Linux64 -Config Debug|Release` builds any program of the repository; output goes to `bin/<Platform>/<Config>`.

Machine settings live in `build/env.ps1`. Copy `build/env.local.example.ps1` to `build/env.local.ps1` to override them:

- `BDS_ROOT`, `BDS_COMMON`: the Delphi installation (default Delphi 13, `Studio\37.0`).
- `LINUX_SDK_ROOT`: the Linux64 SDK imported in the IDE (default `ubuntu26.04.sdk`).
- `WSL_DISTRO`: the WSL distribution that runs the Linux64 tests (default `Ubuntu`).
- `OPENSSL_DIR`: folder with `libcrypto-3-x64.dll` and `libssl-3-x64.dll`.
- `PG_BIN_DIR`: folder with `libpq.dll` for the Win64 PostgreSQL store tests.

### OpenSSL on Windows

The Win64 test executable needs `libcrypto-3-x64.dll` and `libssl-3-x64.dll` next to it or on the `PATH`. After a Win64 build, `build/build.ps1` copies them into the output folder from the first folder that has both: `OPENSSL_DIR`, `C:\Program Files\OpenSSL-Win64\bin`, or the `mingw64\bin` or `ucrt64\bin` folder of Git for Windows.

### Linux64

The Linux64 tests run in WSL and use the system `libcrypto.so.3` and `libssl.so.3` (installed by default on Ubuntu).

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

The tests drop and recreate the `mcpauth_` tables of that database: never point `MCPAUTH_TEST_PG` at a database with data you want to keep.

The FireDAC PostgreSQL driver loads libpq:

- Win64: `libpq.dll` and the DLLs it depends on must be on the `PATH`. `build/test.ps1` puts `PG_BIN_DIR` in front of the `PATH`; by default that is the newest `C:\Program Files\PostgreSQL\<n>\bin`. Without a local PostgreSQL install, unpack the `bin` folder of the official PostgreSQL Windows binaries (zip) anywhere and set `PG_BIN_DIR` in `build/env.local.ps1`.
- Linux64: the system `libpq.so.5`; on Ubuntu `sudo apt-get install -y libpq5`. `build/test.ps1` passes `MCPAUTH_TEST_PG` and `MCPAUTH_PG_VENDORLIB` on to WSL.

`MCPAUTH_PG_VENDORLIB` names another libpq file to load, if needed.

## PostgreSQL store

```delphi
const Driver = TFireDACPgDriver.Create;                 // keep alive as long as connections are made
const Factory: IFireDACConnectionFactory = TFireDACConnectionFactory.Create(ConnectionString);
TFireDACMigrations.Apply(Factory, 'postgres', MigrationsPath);
const Stores = TFireDACStore.CreateSet(Factory, Clock);
```

- `TFireDACConnectionFactory` registers a private, pooled FireDAC connection definition. Every repository call takes a connection from the pool and hands it back, so no connection is shared between threads. The connection string is split on `;`, so values cannot contain one.
- `TFireDACPgDriver` links the PostgreSQL driver and sets its vendor library: `libpq.dll` on Windows, `libpq.so.5` on Linux, or the file you pass.
- `TFireDACMigrations.Apply` runs `<MigrationsPath>/<dialect>/NNNN_*.sql` in order, each file in its own transaction together with its row in the version table (default `mcpauth_schema_version`). Applied files are skipped, so a rerun is safe, and the version table is locked per file so servers that start together apply each file once. An MCP server can keep its own migrations with its own `VersionTable`.
- The schema in `migrations/postgres` uses the prefix `mcpauth_`, `timestamptz` for times and `bytea` for bytes. Times are written with an explicit UTC offset and read back as UTC, whatever the session or machine time zone.
- All PostgreSQL-specific SQL of the repositories is in `TSqlDialect` (`MCPAuth.Store.FireDAC.Dialect`).
- Connections open with `ResourceOptions.SilentMode`, so console and service programs need no FireDAC wait-cursor unit.

## License

MIT, see [LICENSE](LICENSE).
