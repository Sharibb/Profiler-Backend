-- Create schema if it doesn't exist
CREATE SCHEMA IF NOT EXISTS sigh_ai;

-- Set the search path
SET search_path TO sigh_ai;

-- Create users table
CREATE TABLE IF NOT EXISTS sigh_ai.users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  full_name VARCHAR(255) NOT NULL,
  avatar_url VARCHAR(255),
  tier VARCHAR(50) DEFAULT 'basic',
  is_verified BOOLEAN DEFAULT false,
  reset_token VARCHAR(255),
  reset_token_expiry TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create sessions table for connect-pg-simple in the default schema
CREATE TABLE IF NOT EXISTS "session" (
  "sid" varchar NOT NULL COLLATE "default",
  "sess" json NOT NULL,
  "expire" timestamp(6) NOT NULL,
  CONSTRAINT "session_pkey" PRIMARY KEY ("sid")
);

CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");

-- Create notes table
CREATE TABLE IF NOT EXISTS sigh_ai.notes (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES sigh_ai.users(id) ON DELETE CASCADE,
  title VARCHAR(255),
  content TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create hacking_profiles table
CREATE TABLE IF NOT EXISTS sigh_ai.hacking_profiles (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES sigh_ai.users(id) ON DELETE CASCADE,
  platform VARCHAR(50) NOT NULL,
  username VARCHAR(255) NOT NULL,
  api_key VARCHAR(255),
  connected BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, platform)
);

-- Create social_profiles table
CREATE TABLE IF NOT EXISTS sigh_ai.social_profiles (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES sigh_ai.users(id) ON DELETE CASCADE,
  platform VARCHAR(50) NOT NULL,
  username VARCHAR(255) NOT NULL,
  url VARCHAR(255),
  api_key VARCHAR(255),
  connected BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, platform)
);

-- Grant permissions to the database user
GRANT ALL PRIVILEGES ON SCHEMA sigh_ai TO "0mni";
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA sigh_ai TO "0mni";
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA sigh_ai TO "0mni";
GRANT ALL PRIVILEGES ON TABLE "session" TO "0mni"; 