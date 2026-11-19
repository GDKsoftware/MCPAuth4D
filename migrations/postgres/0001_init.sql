-- MCPAuth4D schema for PostgreSQL. Times are UTC (timestamptz); tokens, codes and session ids are stored as SHA-256 hashes only.

CREATE TABLE mcpauth_users (
  id            varchar(64)  PRIMARY KEY,
  display_name  text         NOT NULL,
  created_at    timestamptz  NOT NULL
);

CREATE TABLE mcpauth_linked_accounts (
  id                       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  account_key              text         NOT NULL,
  provider                 text         NOT NULL,
  tenant_id                text         NOT NULL,
  object_id                text         NOT NULL,
  user_id                  varchar(64)  NOT NULL,
  display_name             text         NOT NULL,
  user_name                text         NOT NULL,
  granted_scopes           text         NOT NULL,
  protected_refresh_token  bytea        NOT NULL,
  needs_reconnect          boolean      NOT NULL,
  linked_at                timestamptz  NOT NULL,
  updated_at               timestamptz  NOT NULL
);

CREATE UNIQUE INDEX mcpauth_linked_accounts_account_key ON mcpauth_linked_accounts (account_key);
CREATE INDEX mcpauth_linked_accounts_user_id ON mcpauth_linked_accounts (user_id);

CREATE TABLE mcpauth_clients (
  client_id      varchar(128)  PRIMARY KEY,
  client_name    text          NOT NULL,
  redirect_uris  text          NOT NULL,
  created_at     timestamptz   NOT NULL
);

CREATE TABLE mcpauth_pending_authorizations (
  id                 varchar(128)  PRIMARY KEY,
  purpose            varchar(32)   NOT NULL,
  client_id          text          NOT NULL,
  redirect_uri       text          NOT NULL,
  code_challenge     text          NOT NULL,
  state              text          NOT NULL,
  scope              text          NOT NULL,
  resource           text          NOT NULL,
  user_id            varchar(64)   NOT NULL,
  upstream_provider  text          NOT NULL,
  upstream_verifier  text          NOT NULL,
  expires_at         timestamptz   NOT NULL
);

CREATE INDEX mcpauth_pending_authorizations_expires_at ON mcpauth_pending_authorizations (expires_at);

CREATE TABLE mcpauth_grants (
  code_hash       varchar(128)  PRIMARY KEY,
  client_id       text          NOT NULL,
  redirect_uri    text          NOT NULL,
  code_challenge  text          NOT NULL,
  user_id         varchar(64)   NOT NULL,
  scope           text          NOT NULL,
  resource        text          NOT NULL,
  expires_at      timestamptz   NOT NULL
);

CREATE INDEX mcpauth_grants_expires_at ON mcpauth_grants (expires_at);

CREATE TABLE mcpauth_tokens (
  hash        varchar(128)  PRIMARY KEY,
  kind        varchar(16)   NOT NULL,
  family_id   varchar(128)  NOT NULL,
  user_id     varchar(64)   NOT NULL,
  client_id   text          NOT NULL,
  scope       text          NOT NULL,
  resource    text          NOT NULL,
  consumed    boolean       NOT NULL,
  created_at  timestamptz   NOT NULL,
  expires_at  timestamptz   NOT NULL
);

CREATE INDEX mcpauth_tokens_family_id ON mcpauth_tokens (family_id);
CREATE INDEX mcpauth_tokens_user_id ON mcpauth_tokens (user_id);
CREATE INDEX mcpauth_tokens_expires_at ON mcpauth_tokens (expires_at);

CREATE TABLE mcpauth_sessions (
  id_hash     varchar(128)  PRIMARY KEY,
  user_id     varchar(64)   NOT NULL,
  csrf_token  text          NOT NULL,
  expires_at  timestamptz   NOT NULL
);

CREATE INDEX mcpauth_sessions_expires_at ON mcpauth_sessions (expires_at);
