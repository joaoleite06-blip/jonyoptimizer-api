const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');

const db = new Database('database.sqlite');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    discord_id TEXT UNIQUE,
    email TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE IF NOT EXISTS licenses (
    id TEXT PRIMARY KEY,
    license_key_hash TEXT UNIQUE,
    user_id TEXT,
    product_id TEXT DEFAULT 'optimizer_pro',
    status TEXT DEFAULT 'active',
    max_devices INTEGER DEFAULT 1,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    revoked_at DATETIME
  );
  
  CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    license_id TEXT,
    device_fingerprint TEXT,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'active'
  );
  
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    device_id TEXT,
    token_hash TEXT,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

module.exports = db;