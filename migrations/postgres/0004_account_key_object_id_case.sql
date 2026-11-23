-- The object id in account_key keeps its case; only the provider name, the tenant id and a GUID object id are lower-case.
-- Earlier versions stored the whole key in lower case. The object_id column always kept the case, so the key is rebuilt from it.
-- The refresh token of a rebuilt account was encrypted for the old key and cannot be read any more: the account is marked
-- for reconnect, and the next sign-in with it stores a new refresh token.

UPDATE mcpauth_linked_accounts
SET account_key = split_part(account_key, ':', 1) || ':' || split_part(account_key, ':', 2) || ':' || object_id,
    needs_reconnect = true
WHERE object_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  AND account_key <> split_part(account_key, ':', 1) || ':' || split_part(account_key, ':', 2) || ':' || object_id;
