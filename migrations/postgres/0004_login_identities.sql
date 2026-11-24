-- A user signs in only with his login identity. Linked accounts give upstream access and may be linked by several users,
-- each with a refresh token of his own.

CREATE TABLE mcpauth_login_identities (
  id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  identity_key   text         NOT NULL,
  provider       text         NOT NULL,
  tenant_id      text         NOT NULL,
  object_id      text         NOT NULL,
  user_id        varchar(64)  NOT NULL REFERENCES mcpauth_users (id),
  user_name      text         NOT NULL,
  created_at     timestamptz  NOT NULL,
  last_login_at  timestamptz  NOT NULL
);

CREATE UNIQUE INDEX mcpauth_login_identities_identity_key ON mcpauth_login_identities (identity_key);
CREATE INDEX mcpauth_login_identities_user_id ON mcpauth_login_identities (user_id);

DROP INDEX mcpauth_linked_accounts_account_key;
CREATE UNIQUE INDEX mcpauth_linked_accounts_user_account ON mcpauth_linked_accounts (user_id, account_key);
CREATE INDEX mcpauth_linked_accounts_account_key ON mcpauth_linked_accounts (account_key);

-- Every existing user signs in with his oldest linked account. Links without a user are left alone, and an account
-- that another user linked too never becomes an identity: that would let the other user sign in as this one.
-- TFireDACLoginIdentityRepository.AddMissing runs the same statement.
INSERT INTO mcpauth_login_identities (identity_key, provider, tenant_id, object_id, user_id, user_name, created_at, last_login_at)
SELECT DISTINCT ON (a.user_id) a.account_key, a.provider, a.tenant_id, a.object_id, a.user_id, a.user_name, a.linked_at, a.updated_at
FROM mcpauth_linked_accounts a
JOIN mcpauth_users u ON u.id = a.user_id
WHERE NOT EXISTS (SELECT 1 FROM mcpauth_login_identities i WHERE i.user_id = a.user_id)
  AND NOT EXISTS (SELECT 1 FROM mcpauth_linked_accounts o WHERE o.account_key = a.account_key AND o.user_id <> a.user_id)
ORDER BY a.user_id, a.linked_at, a.id
ON CONFLICT (identity_key) DO NOTHING;
