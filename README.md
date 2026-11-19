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

### OpenSSL on Windows

The Win64 test executable needs `libcrypto-3-x64.dll` and `libssl-3-x64.dll` next to it or on the `PATH`. After a Win64 build, `build/build.ps1` copies them into the output folder from the first folder that has both: `OPENSSL_DIR`, `C:\Program Files\OpenSSL-Win64\bin`, or the `mingw64\bin` or `ucrt64\bin` folder of Git for Windows.

### Linux64

The Linux64 tests run in WSL and use the system `libcrypto.so.3` and `libssl.so.3` (installed by default on Ubuntu).

## License

MIT, see [LICENSE](LICENSE).
