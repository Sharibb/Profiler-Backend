require('dotenv').config();
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

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

// Default bookmark categories to populate
const DEFAULT_CATEGORIES = [
  {
    external_id: "security-tools",
    name: "Security Tools",
    icon: "shield-alert",
    bookmarks: [
      { external_id: "st-1", title: "Kali Linux", url: "https://www.kali.org/", color: "bg-blue-500" },
      { external_id: "st-2", title: "Metasploit", url: "https://www.metasploit.com/", color: "bg-red-500" },
      { external_id: "st-3", title: "Wireshark", url: "https://www.wireshark.org/", color: "bg-green-500" },
      { external_id: "st-4", title: "Burp Suite", url: "https://portswigger.net/burp", color: "bg-orange-500" },
      { external_id: "st-5", title: "OWASP", url: "https://owasp.org/", color: "bg-purple-500" },
      { external_id: "st-6", title: "Nmap", url: "https://nmap.org/", color: "bg-cyan-500" }
    ]
  },
  {
    external_id: "learning",
    name: "Learning Resources",
    icon: "book-open",
    bookmarks: [
      { external_id: "lr-1", title: "TryHackMe", url: "https://tryhackme.com/", color: "bg-red-500" },
      { external_id: "lr-2", title: "HackTheBox", url: "https://www.hackthebox.com/", color: "bg-green-500" },
      { external_id: "lr-3", title: "Cybrary", url: "https://www.cybrary.it/", color: "bg-blue-500" },
      { external_id: "lr-4", title: "PortSwigger Academy", url: "https://portswigger.net/web-security", color: "bg-orange-500" },
      { external_id: "lr-5", title: "Hack The Box Academy", url: "https://academy.hackthebox.com/", color: "bg-green-500" }
    ]
  },
  {
    external_id: "news",
    name: "Security News",
    icon: "newspaper",
    bookmarks: [
      { external_id: "n-1", title: "Krebs on Security", url: "https://krebsonsecurity.com/", color: "bg-red-500" },
      { external_id: "n-2", title: "The Hacker News", url: "https://thehackernews.com/", color: "bg-blue-500" },
      { external_id: "n-3", title: "Threatpost", url: "https://threatpost.com/", color: "bg-purple-500" },
      { external_id: "n-4", title: "Bleeping Computer", url: "https://www.bleepingcomputer.com/", color: "bg-cyan-500" }
    ]
  },
  {
    external_id: "coding",
    name: "Coding Resources",
    icon: "code",
    bookmarks: [
      { external_id: "c-1", title: "GitHub", url: "https://github.com/", color: "bg-slate-500" },
      { external_id: "c-2", title: "Stack Overflow", url: "https://stackoverflow.com/", color: "bg-orange-500" },
      { external_id: "c-3", title: "MDN Web Docs", url: "https://developer.mozilla.org/", color: "bg-blue-500" },
      { external_id: "c-4", title: "W3Schools", url: "https://www.w3schools.com/", color: "bg-green-500" }
    ]
  },
  {
    external_id: "tools",
    name: "Useful Tools",
    icon: "wrench",
    bookmarks: [
      { external_id: "t-1", title: "CyberChef", url: "https://gchq.github.io/CyberChef/", color: "bg-yellow-500" },
      { external_id: "t-2", title: "VirusTotal", url: "https://www.virustotal.com/", color: "bg-blue-500" },
      { external_id: "t-3", title: "Shodan", url: "https://www.shodan.io/", color: "bg-red-500" },
      { external_id: "t-4", title: "GTFOBins", url: "https://gtfobins.github.io/", color: "bg-purple-500" }
    ]
  },
  {
    external_id: "work",
    name: "Work",
    icon: "briefcase",
    bookmarks: [
      { external_id: "w-1", title: "Gmail", url: "https://mail.google.com/", color: "bg-red-500" },
      { external_id: "w-2", title: "Google Drive", url: "https://drive.google.com/", color: "bg-yellow-500" },
      { external_id: "w-3", title: "Slack", url: "https://slack.com/", color: "bg-purple-500" },
      { external_id: "w-4", title: "Notion", url: "https://www.notion.so/", color: "bg-slate-500" }
    ]
  },
  {
    external_id: "ctf",
    name: "CTF Platforms",
    icon: "gamepad",
    bookmarks: [
      { external_id: "ctf-1", title: "CTFtime", url: "https://ctftime.org/", color: "bg-green-500" },
      { external_id: "ctf-2", title: "PicoCTF", url: "https://picoctf.org/", color: "bg-blue-500" },
      { external_id: "ctf-3", title: "VulnHub", url: "https://www.vulnhub.com/", color: "bg-red-500" },
      { external_id: "ctf-4", title: "Root Me", url: "https://www.root-me.org/", color: "bg-purple-500" }
    ]
  },
];

/**
 * Initialize the entire database schema from scratch
 */
async function setupFullSchema() {
  const client = await pool.connect();
  
  try {
    // Read the schema.sql file
    const schemaPath = path.join(__dirname, 'schema.sql');
    const schemaSql = fs.readFileSync(schemaPath, 'utf8')
      // Replace all instances of sigh_ai with DEUSS in the schema
      .replace(/sigh_ai/g, 'DEUSS');
    
    console.log('Running full schema setup...');
    
    // Execute the schema SQL as a transaction
    await client.query('BEGIN');
    
    // Split the SQL by semicolons to execute each statement separately
    // Note: This is a simple approach and won't work for complex SQL with semicolons in strings or functions
    const statements = schemaSql.split(';')
      .filter(statement => statement.trim().length > 0);
    
    for (const statement of statements) {
      await client.query(statement);
    }
    
    await client.query('COMMIT');
    
    console.log('Schema setup completed successfully!');
    console.log('Tables created:');
    
    // List all created tables to verify
    const tablesResult = await client.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'DEUSS'
    `);
    
    tablesResult.rows.forEach(row => {
      console.log(`- ${row.table_name}`);
    });
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error setting up schema:', error);
    process.exit(1);
  } finally {
    client.release();
  }
}

/**
 * Add api_key column to social_profiles table
 */
async function addApiKeyColumn() {
  const client = await pool.connect();
  
  try {
    console.log('Checking for api_key column in social_profiles table...');
    
    // Set the search path
    await client.query('SET search_path TO DEUSS');
    
    // Check if column already exists
    const checkResult = await client.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_schema = 'DEUSS' 
      AND table_name = 'social_profiles'
      AND column_name = 'api_key'
    `);
    
    if (checkResult.rows.length > 0) {
      console.log('api_key column already exists in social_profiles table');
    } else {
      // Add the api_key column
      await client.query(`
        ALTER TABLE DEUSS.social_profiles 
        ADD COLUMN api_key TEXT
      `);
      console.log('Successfully added api_key column to social_profiles table');
    }
    
    // Verify all columns in the table
    const verifyResult = await client.query(`
      SELECT column_name, data_type 
      FROM information_schema.columns 
      WHERE table_schema = 'DEUSS' 
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
  }
}

/**
 * Add tags column to notes table
 */
async function addTagsColumn() {
  const client = await pool.connect();
  
  try {
    console.log('Checking for tags column in notes table...');
    
    // Check if the column already exists to avoid errors
    const checkColumnQuery = `
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = 'DEUSS'
        AND table_name = 'notes'
        AND column_name = 'tags';
    `;
    
    const checkResult = await client.query(checkColumnQuery);
    
    if (checkResult.rows.length === 0) {
      // Column doesn't exist, let's add it
      console.log('Tags column not found. Adding it now...');
      
      await client.query('BEGIN');
      
      // Add the tags column as a text array with default empty array
      const addColumnQuery = `
        ALTER TABLE DEUSS.notes
        ADD COLUMN tags TEXT[] DEFAULT '{}';
      `;
      
      await client.query(addColumnQuery);
      
      // Commit the transaction
      await client.query('COMMIT');
      
      console.log('Successfully added tags column to notes table!');
    } else {
      console.log('Tags column already exists. No migration needed.');
    }
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error adding tags column:', error);
  } finally {
    client.release();
  }
}

/**
 * Add default_bookmarks_added column to users table
 */
async function addDefaultBookmarksColumn() {
  const client = await pool.connect();
  
  try {
    console.log('Checking for default_bookmarks_added column in users table...');
    
    // Check if default_bookmarks_added column exists in users table
    const columnCheckResult = await client.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_schema = 'DEUSS' 
      AND table_name = 'users' 
      AND column_name = 'default_bookmarks_added'
    `);
    
    if (columnCheckResult.rows.length === 0) {
      console.log('Adding missing default_bookmarks_added column to users table');
      
      await client.query('BEGIN');
      
      // Add the missing column
      await client.query(`
        ALTER TABLE DEUSS.users
        ADD COLUMN default_bookmarks_added BOOLEAN DEFAULT false
      `);
      
      await client.query('COMMIT');
      
      console.log('Column added successfully');
    } else {
      console.log('Column default_bookmarks_added already exists in users table');
    }
    
  } catch (error) {
    // Roll back the transaction in case of error
    await client.query('ROLLBACK');
    console.error('Error updating database schema:', error);
  } finally {
    // Release the client back to the pool
    client.release();
  }
}

/**
 * Populate default bookmarks in the database
 */
async function populateDefaultBookmarks() {
  const client = await pool.connect();
  
  try {
    // Start a transaction
    await client.query('BEGIN');
    
    console.log('Populating default bookmark categories and bookmarks...');
    
    // First clear existing default bookmarks (for re-running the script)
    await client.query('DELETE FROM DEUSS.default_bookmarks');
    await client.query('DELETE FROM DEUSS.default_bookmark_categories');
    
    // Add each category with its bookmarks
    for (const category of DEFAULT_CATEGORIES) {
      // Insert category
      const categoryResult = await client.query(
        'INSERT INTO DEUSS.default_bookmark_categories (name, icon, external_id) VALUES ($1, $2, $3) RETURNING id',
        [category.name, category.icon, category.external_id]
      );
      
      const categoryId = categoryResult.rows[0].id;
      console.log(`Added category: ${category.name} (ID: ${categoryId})`);
      
      // Insert bookmarks for this category
      for (const bookmark of category.bookmarks) {
        await client.query(
          'INSERT INTO DEUSS.default_bookmarks (category_id, title, url, color, external_id) VALUES ($1, $2, $3, $4, $5)',
          [categoryId, bookmark.title, bookmark.url, bookmark.color, bookmark.external_id]
        );
        console.log(`  - Added bookmark: ${bookmark.title}`);
      }
    }
    
    // Commit the transaction
    await client.query('COMMIT');
    console.log('Default bookmarks populated successfully!');
    
  } catch (error) {
    // Roll back the transaction in case of error
    await client.query('ROLLBACK');
    console.error('Error populating default bookmarks:', error);
  } finally {
    // Release the client back to the pool
    client.release();
  }
}

/**
 * Main function to run all schema updates
 */
async function manageSchema(options = {}) {
  try {
    const {
      fullSetup = false,
      addApiKey = false,
      addTags = false,
      addDefaultBookmarks = false,
      populateBookmarks = false,
      runAll = false
    } = options;
    
    // If no specific options are provided, show help
    if (!fullSetup && !addApiKey && !addTags && !addDefaultBookmarks && !populateBookmarks && !runAll) {
      console.log(`
Schema Manager - Usage:
-----------------------
node schema-manager.js --full-setup       # Run complete schema setup from scratch
node schema-manager.js --add-api-key      # Add API key column to social_profiles table
node schema-manager.js --add-tags         # Add tags column to notes table
node schema-manager.js --add-bookmarks    # Add default_bookmarks_added column to users table
node schema-manager.js --populate         # Populate default bookmarks
node schema-manager.js --all              # Run all updates
      `);
      return;
    }
    
    if (fullSetup || runAll) {
      console.log('\n=== Running Full Schema Setup ===');
      await setupFullSchema();
    }
    
    if (addApiKey || runAll) {
      console.log('\n=== Adding API Key Column ===');
      await addApiKeyColumn();
    }
    
    if (addTags || runAll) {
      console.log('\n=== Adding Tags Column ===');
      await addTagsColumn();
    }
    
    if (addDefaultBookmarks || runAll) {
      console.log('\n=== Adding Default Bookmarks Column ===');
      await addDefaultBookmarksColumn();
    }
    
    if (populateBookmarks || runAll) {
      console.log('\n=== Populating Default Bookmarks ===');
      await populateDefaultBookmarks();
    }
    
    console.log('\nAll schema operations completed successfully!');
  } catch (error) {
    console.error('Error in schema management:', error);
    process.exit(1);
  } finally {
    // Close the pool when all operations are done
    await pool.end();
    console.log('Database connection closed');
  }
}

// Parse command line arguments
const args = process.argv.slice(2);
const options = {
  fullSetup: args.includes('--full-setup'),
  addApiKey: args.includes('--add-api-key'),
  addTags: args.includes('--add-tags'),
  addDefaultBookmarks: args.includes('--add-bookmarks'),
  populateBookmarks: args.includes('--populate'),
  runAll: args.includes('--all')
};

// Run the schema manager with the provided options
manageSchema(options); 