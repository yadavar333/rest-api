CREATE TABLE IF NOT EXISTS users (
  id        SERIAL PRIMARY KEY,
  email     VARCHAR(255) UNIQUE NOT NULL,
  password  VARCHAR(255) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS posts (
  id         SERIAL PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title      VARCHAR(255) NOT NULL,
  content    TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id         SERIAL PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash VARCHAR(255) UNIQUE NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_posts_user_id        ON posts(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user  ON refresh_tokens(user_id);
