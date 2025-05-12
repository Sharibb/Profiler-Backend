-- Create schema if it doesn't exist
CREATE SCHEMA IF NOT EXISTS DEUSS;

-- Set the search path
SET search_path TO DEUSS;

-- Create users table
CREATE TABLE IF NOT EXISTS DEUSS.users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  full_name VARCHAR(255) NOT NULL,
  avatar_url VARCHAR(255),
  tier VARCHAR(50) DEFAULT 'basic',
  is_verified BOOLEAN DEFAULT false,
  reset_token VARCHAR(255),
  reset_token_expiry TIMESTAMP,
  default_bookmarks_added BOOLEAN DEFAULT false,
  country VARCHAR(100),
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
CREATE TABLE IF NOT EXISTS DEUSS.notes (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES DEUSS.users(id) ON DELETE CASCADE,
  title VARCHAR(255),
  content TEXT NOT NULL,
  tags TEXT[] DEFAULT '{}',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create hacking_profiles table
CREATE TABLE IF NOT EXISTS DEUSS.hacking_profiles (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES DEUSS.users(id) ON DELETE CASCADE,
  platform VARCHAR(50) NOT NULL,
  username VARCHAR(255) NOT NULL,
  api_key VARCHAR(255),
  connected BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, platform)
);

-- Create social_profiles table
CREATE TABLE IF NOT EXISTS DEUSS.social_profiles (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES DEUSS.users(id) ON DELETE CASCADE,
  platform VARCHAR(50) NOT NULL,
  username VARCHAR(255) NOT NULL,
  url VARCHAR(255),
  api_key VARCHAR(255),
  connected BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, platform)
);

-- Create bookmark_categories table
CREATE TABLE IF NOT EXISTS DEUSS.bookmark_categories (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES DEUSS.users(id) ON DELETE CASCADE,
  name VARCHAR(100) NOT NULL,
  icon VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create bookmarks table
CREATE TABLE IF NOT EXISTS DEUSS.bookmarks (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES DEUSS.users(id) ON DELETE CASCADE,
  category_id INTEGER REFERENCES DEUSS.bookmark_categories(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  url TEXT NOT NULL,
  color VARCHAR(50),
  icon VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create default_bookmark_categories table
CREATE TABLE IF NOT EXISTS DEUSS.default_bookmark_categories (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  icon VARCHAR(255),
  external_id VARCHAR(100) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create default_bookmarks table
CREATE TABLE IF NOT EXISTS DEUSS.default_bookmarks (
  id SERIAL PRIMARY KEY,
  category_id INTEGER REFERENCES DEUSS.default_bookmark_categories(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  url TEXT NOT NULL,
  color VARCHAR(50),
  icon VARCHAR(255),
  external_id VARCHAR(100) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Grant permissions to the database user
GRANT ALL PRIVILEGES ON SCHEMA DEUSS TO "DEUSS_owner";
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA DEUSS TO "DEUSS_owner";
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA DEUSS TO "DEUSS_owner";
GRANT ALL PRIVILEGES ON TABLE "session" TO "DEUSS_owner";
