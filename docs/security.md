# Security notes

This page describes how the auth server protects sign-ins and tokens, and the trade-offs and known limits that an operator should know about. The architecture itself is in the [README](../README.md#architecture).

## Sign-in binding

Every upstream sign-in (an authorization request of a client, a portal login, linking or reconnecting an account) is bound to the browser that started it.

- When a sign-in starts, the server sets a short-lived login cookie (`__Host-mcpauth_login`, or `mcpauth_login` without `https`) that holds a random value. The pending sign-in keeps only the SHA-256 of that value. The cookie is `HttpOnly`, `SameSite=Lax`, `Secure` (with `https`) and lives as long as the pending sign-in (`PendingSeconds`, 10 minutes by default).
- The upstream callback is rejected with an error page, before the upstream code is redeemed, when the browser does not send the login cookie of that sign-in. A callback URL that is handed to someone else therefore cannot complete the sign-in in their browser.
- Linking or reconnecting an account also requires that the callback arrives in the session of the user who started linking. That session stays; it is not replaced by a new one.
- One browser can run one upstream sign-in at a time: starting a second one replaces the login cookie of the first, which then fails with "started in another browser". Start it again.

## Cookies

With an `https` issuer every cookie is `Secure` and carries the `__Host-` prefix (`__Host-mcpauth_session`, `__Host-mcpauth_login`). The browser then only accepts the cookie with `Path=/` and without a `Domain`, so another site on a sibling subdomain (for example another MCP server under the same parent domain) cannot plant or overwrite it. All cookies are `HttpOnly` and `SameSite=Lax`.

## Refresh tokens

- **Rotation.** Every refresh returns a new refresh token; the old one is consumed. A consumed refresh token that comes back means it leaked, and the whole family (all tokens of that grant) is revoked.
- **Concurrent refreshes.** When two requests refresh with the same refresh token at the same moment, one wins and the other counts as reuse, so the family is revoked and the client has to authorize again. This is deliberate (strict rotation as in the OAuth 2.1 security recommendations). A revoked family stays revoked: a new token pair that the winning request saves after the revocation is never active.
- **Lifetime.** A family has no absolute lifetime: every refresh starts a new `RefreshTokenDays` period (30 days by default). A user ends a grant on the account page; the account page and `/revoke` revoke the whole family.
- **`/revoke`.** Only public clients are registered, so `client_id` is not authenticated and `/revoke` does not check that the token belongs to it. Whoever holds a token can already use it.
- **Reused authorization code.** A second redemption of an authorization code fails with `invalid_grant`, but it does not revoke the tokens issued from the first redemption (RFC 6749 4.1.2 recommends that). PKCE and the single use of the code limit the impact.

## Caches at the MCP server

- An MCP server caches a positive introspection result for up to 60 seconds (`IntrospectionCacheSeconds`), so a revoked access token can keep working at that MCP server for up to a minute.
- `IUpstreamAccounts.GetAccessToken` caches an upstream access token until a minute before it expires (about an hour for Microsoft). After a user unlinks an account on the account page, an MCP server that already holds a cached token for it can keep using that token until it expires. Restart the MCP server to drop its cache at once.

## Upstream scopes

- At sign-in the Microsoft provider asks for the union of the scopes of all resources. A refresh asks only for the scopes the account granted, because asking for a scope the account never consented to fails the whole refresh.
- When a resource needs a scope that an account has not granted, for example after a resource with a new scope was added, that resource gets `reconnect_required` with reason `missing_scopes`; other resources keep working. The user reconnects the account on the account page.
- The scope of every refresh response is stored, so a scope that an administrator removed from the grant also turns into `missing_scopes`.
- Reconnecting with a different identity than the flagged account links that identity as an extra account; the flagged account stays flagged and visible on the account page, where the user can unlink it.

## Stored data and cleanup

- Tokens, codes, session ids, upstream state and service secrets are stored only as SHA-256 hashes. Upstream refresh tokens are encrypted with AES-256-GCM.
- Pending sign-ins and browser sessions hold a few values in plain text: the client's `state` (it must be returned verbatim), the PKCE verifier of the upstream sign-in (useless without the upstream code) and the CSRF token of the session (useless without the session id, which is stored as a hash).
- The maintenance thread deletes expired tokens, sessions, pending sign-ins and authorization codes once an hour, so these values only stay on disk for their short lifetime plus at most an hour.

## Client registration

Dynamic client registration (`POST /register`) is open, as MCP clients expect. A registration holds at most 10 redirect URIs of at most 2000 characters, and the redirect URIs must pass the redirect policy. Registered clients are never deleted. If the `mcpauth_clients` table grows from abuse, delete clients that have no tokens, for example clients older than 30 days whose `client_id` does not appear in `mcpauth_tokens`.

## Errors at the upstream callback

When the user cancels the upstream sign-in or the upstream provider answers with an error, the callback shows an error page. For an authorization request of a client, it does not redirect `error=access_denied` to the client, so the client keeps waiting until it times out.
