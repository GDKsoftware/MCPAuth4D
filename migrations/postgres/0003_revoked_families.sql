-- A revoked refresh family stays revoked: tokens that a concurrent refresh saves after the revocation are never active.

CREATE TABLE mcpauth_revoked_families (
  family_id   varchar(128)  PRIMARY KEY,
  revoked_at  timestamptz   NOT NULL
);

CREATE INDEX mcpauth_revoked_families_revoked_at ON mcpauth_revoked_families (revoked_at);
