require('dotenv').config();
const { Pool } = require('pg');

// PostgreSQL Configuration - use environment variable or fallback to default
const connectionString = process.env.DATABASE_URL;

const pool = new Pool({
  connectionString,
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false
  } : false
});

async function addApiKeyColumn() {
  const client = await pool.connect();
  
  try {
    console.log('Connected to the database');
    
    // Set the search path
    await client.query('SET search_path TO sigh_ai');
    console.log('Schema set to sigh_ai');
    
    // Check if column already exists
    const checkResult = await client.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_schema = 'sigh_ai' 
      AND table_name = 'social_profiles'
      AND column_name = 'api_key'
    `);
    
    if (checkResult.rows.length > 0) {
      console.log('api_key column already exists in social_profiles table');
    } else {
      // Add the api_key column
      await client.query(`
        ALTER TABLE sigh_ai.social_profiles 
        ADD COLUMN api_key TEXT
      `);
      console.log('Successfully added api_key column to social_profiles table');
    }
    
    // Verify all columns in the table
    const verifyResult = await client.query(`
      SELECT column_name, data_type 
      FROM information_schema.columns 
      WHERE table_schema = 'sigh_ai' 
      AND table_name = 'social_profiles'
      ORDER BY ordinal_position
    `);
    
    console.log('\nCurrent social_profiles table structure:');
    verifyResult.rows.forEach(row => {
      console.log(`- ${row.column_name} (${row.data_type})`);
    });
    
  } catch (error) {
    console.error('Error adding api_key column:', error);
  } finally {
    client.release();
    await pool.end();
    console.log('Database connection closed');
  }
}

// Run the migration
addApiKeyColumn().catch(err => {
  console.error('Unhandled error in script:', err);
  process.exit(1);
}); 