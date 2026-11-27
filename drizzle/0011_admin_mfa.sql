ALTER TABLE user ADD two_factor_enabled integer DEFAULT false;
--> statement-breakpoint
CREATE TABLE two_factor (
  id text PRIMARY KEY NOT NULL,secret text NOT NULL,backup_codes text NOT NULL,
  user_id text NOT NULL REFERENCES user(id) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE INDEX two_factor_user_idx ON two_factor(user_id);
--> statement-breakpoint
CREATE TABLE admin_mfa_sessions (
  session_id text PRIMARY KEY REFERENCES session(id) ON DELETE CASCADE,
  user_id text NOT NULL REFERENCES user(id) ON DELETE CASCADE,
  verified_at integer NOT NULL,expires_at integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE admin_mfa_codes (
  user_id text NOT NULL REFERENCES user(id) ON DELETE CASCADE,code_hash text NOT NULL,expires_at integer NOT NULL,
  PRIMARY KEY(user_id,code_hash)
);
--> statement-breakpoint
CREATE TABLE admin_security_log (
  id text PRIMARY KEY,recorded_at integer NOT NULL,event text NOT NULL,user_id text
);
--> statement-breakpoint
CREATE TABLE admin_mfa_limits (user_id text PRIMARY KEY,available_at integer NOT NULL);
