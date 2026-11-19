-- Binds every upstream sign-in to the browser that started it: the hash of its login cookie.

ALTER TABLE mcpauth_pending_authorizations ADD COLUMN browser_binding_hash varchar(128) NOT NULL DEFAULT '';
