const { Pool } = require('pg');
const { AsyncLocalStorage } = require('node:async_hooks');

let pool;
function getPool(){
  if (pool) return pool;
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error('DATABASE_URL is required (Supabase Postgres connection string).');
  }
  pool = new Pool({ connectionString, ssl: { rejectUnauthorized: false }, max: 5 });
  return pool;
}

const als = new AsyncLocalStorage();

// Tables whose primary key is not a serial "id" column — never auto-append RETURNING id for these.
const NO_ID_TABLES = new Set(['participants', 'settings']);

function currentClient() {
  return als.getStore() || getPool();
}

// Convert sqlite-style "?" positional placeholders into Postgres "$1,$2,..." placeholders.
// The SQL strings in this app never contain a literal "?" character outside of placeholders.
function toPg(sql) {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

function maybeAddReturning(sql) {
  const trimmed = sql.trim();
  if (!/^insert\s+into/i.test(trimmed)) return sql;
  if (/returning/i.test(trimmed)) return sql;
  const m = trimmed.match(/^insert\s+into\s+([a-zA-Z_"]+)/i);
  const table = m ? m[1].replace(/"/g, '') : null;
  if (table && NO_ID_TABLES.has(table)) return sql;
  return sql + ' RETURNING id';
}

function prepare(sql) {
  return {
    async get(...args) {
      const pgSql = toPg(sql);
      const res = await currentClient().query(pgSql, args);
      return res.rows[0];
    },
    async all(...args) {
      const pgSql = toPg(sql);
      const res = await currentClient().query(pgSql, args);
      return res.rows;
    },
    async run(...args) {
      const withReturning = maybeAddReturning(sql);
      const pgSql = toPg(withReturning);
      const res = await currentClient().query(pgSql, args);
      return {
        lastInsertRowid: res.rows[0] ? res.rows[0].id : undefined,
        changes: res.rowCount,
      };
    },
  };
}

// Mirrors the previous better-sqlite3-style db.transaction(fn) -> fn wrapped in BEGIN/COMMIT/ROLLBACK.
// fn may be async and should use db.prepare(...).get/.all/.run internally as usual.
function transaction(fn) {
  return async (...args) => {
    const client = await getPool().connect();
    try {
      await client.query('BEGIN');
      const result = await als.run(client, () => fn(...args));
      await client.query('COMMIT');
      return result;
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch (_) {}
      throw err;
    } finally {
      client.release();
    }
  };
}

module.exports = { prepare, transaction, get pool() { return getPool(); } };
