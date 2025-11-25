CREATE TABLE IF NOT EXISTS schema_migrations (
  version text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    user_id VARCHAR(15) NOT NULL DEFAULT() '111111111111111', 
    username VARCHAR(50) NOT NULL DEFAULT()'placeholder_joe',
    email VARCHAR(50) NOT NULL DEFAULT()'placeholder_joe@email.com',
     
);
