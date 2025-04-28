require('dotenv').config();
const { Pool } = require('pg');

// Ensure required environment variables are set
if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL environment variable is not set');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

async function updateSchema() {
  try {
    // Add api_key column to social_profiles table if it doesn't exist
    await pool.query(`
      ALTER TABLE sigh_ai.social_profiles 
      ADD COLUMN IF NOT EXISTS api_key TEXT
    `);
    console.log('Added api_key column to social_profiles table');

    // Verify the column was added
    const result = await pool.query(`
      SELECT column_name, data_type 
      FROM information_schema.columns 
      WHERE table_schema = 'sigh_ai' 
      AND table_name = 'social_profiles'
    `);
    
    console.log('Current social_profiles table columns:');
    result.rows.forEach(row => {
      console.log(`- ${row.column_name} (${row.data_type})`);
    });

    console.log('Schema update completed successfully');
    
    // Close the pool
    await pool.end();
  } catch (error) {
    console.error('Error updating schema:', error);
    process.exit(1);
  }
}

updateSchema(); 