#!/usr/bin/env node
/**
 * Sync SAM (Simple Admin Mod) bans to data/bans.json.
 * Use when your Garry's Mod server runs SAM and you want the website to show the same bans.
 *
 * Option 1 — MySQL (same database as SAM):
 *   Set env: SAM_MYSQL_HOST, SAM_MYSQL_USER, SAM_MYSQL_PASSWORD, SAM_MYSQL_DATABASE
 *   Then: node scripts/sync-sam-bans.js
 *
 * Option 2 — SQLite (copy the .db file from your game server, then run):
 *   Set env: SAM_SQLITE_PATH=/path/to/your/sam.sqlite  (or pass as first arg)
 *   Requires: npm install better-sqlite3
 *   Then: node scripts/sync-sam-bans.js
 *
 * Optional: SAM_SERVER_NAME="My Server"  (default: "Server")
 * Optional: DATA_DIR=./data  (default: ./data)
 */

const fs = require("fs");
const path = require("path");

const dataDir = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(__dirname, "..", "data");
const bansFile = path.join(dataDir, "bans.json");
const serverName = process.env.SAM_SERVER_NAME || "Server";
const now = Math.floor(Date.now() / 1000);

function normalizeBan(r) {
  const unbanDate = r.unban_date != null ? Number(r.unban_date) : 0;
  const expiresAt = unbanDate === 0 ? null : new Date(unbanDate * 1000).toISOString().slice(0, 19).replace("T", "T");
  let length = "Permanent";
  if (unbanDate > 0) {
    const mins = Math.max(0, Math.floor((unbanDate - now) / 60));
    if (mins < 60) length = mins + " min";
    else if (mins < 1440) length = Math.floor(mins / 60) + " hours";
    else length = Math.floor(mins / 1440) + " days";
  }
  return {
    id: r.id,
    date: null,
    playerName: (r.name && String(r.name).trim()) || null,
    steamId: r.steamid || "",
    length,
    staff: (r.admin_name && String(r.admin_name).trim()) || (r.admin === "Console" ? "Console" : r.admin || ""),
    reason: r.reason || "",
    server: serverName,
    expiresAt,
    unbanned: false,
  };
}

async function fetchFromMysql() {
  const host = process.env.SAM_MYSQL_HOST;
  const database = process.env.SAM_MYSQL_DATABASE;
  if (!host || !database) return null;
  try {
    const mysql = require("mysql2/promise");
    const conn = await mysql.createConnection({
      host,
      port: process.env.SAM_MYSQL_PORT ? Number(process.env.SAM_MYSQL_PORT) : 3306,
      user: process.env.SAM_MYSQL_USER || "",
      password: process.env.SAM_MYSQL_PASSWORD || "",
      database,
    });
    const [rows] = await conn.query(
      `SELECT sam_bans.id, sam_bans.steamid, sam_bans.reason, sam_bans.admin, sam_bans.unban_date,
              IFNULL(p1.name, '') AS name, IFNULL(p2.name, '') AS admin_name
       FROM sam_bans
       LEFT JOIN sam_players AS p1 ON sam_bans.steamid = p1.steamid
       LEFT JOIN sam_players AS p2 ON sam_bans.admin = p2.steamid
       WHERE (sam_bans.unban_date >= ? OR sam_bans.unban_date = 0)
       ORDER BY sam_bans.id DESC`,
      [now]
    );
    await conn.end();
    return Array.isArray(rows) ? rows.map(normalizeBan) : [];
  } catch (e) {
    console.error("MySQL error:", e.message);
    return null;
  }
}

function fetchFromSqlite(dbPath) {
  if (!dbPath) dbPath = process.env.SAM_SQLITE_PATH;
  const argPath = process.argv[2];
  if (argPath && argPath !== "--help") dbPath = path.resolve(argPath);
  if (!dbPath || !fs.existsSync(dbPath)) {
    if (process.argv[2] === "--help") return null;
    console.error("SQLite path missing or file not found. Set SAM_SQLITE_PATH or pass path as first argument.");
    return null;
  }
  let Database;
  try {
    Database = require("better-sqlite3");
  } catch (e) {
    console.error("For SQLite support run: npm install better-sqlite3");
    return null;
  }
  const db = new Database(dbPath, { readonly: true });
  try {
    const stmt = db.prepare(
      `SELECT sam_bans.id, sam_bans.steamid, sam_bans.reason, sam_bans.admin, sam_bans.unban_date,
              IFNULL(p1.name, '') AS name, IFNULL(p2.name, '') AS admin_name
       FROM sam_bans
       LEFT JOIN sam_players AS p1 ON sam_bans.steamid = p1.steamid
       LEFT JOIN sam_players AS p2 ON sam_bans.admin = p2.steamid
       WHERE (sam_bans.unban_date >= ? OR sam_bans.unban_date = 0)
       ORDER BY sam_bans.id DESC`
    );
    const rows = stmt.all(now);
    return Array.isArray(rows) ? rows.map(normalizeBan) : [];
  } finally {
    db.close();
  }
}

async function main() {
  if (process.argv[2] === "--help") {
    console.log(require("path").basename(__filename) + " [sqlite_path]");
    console.log("");
    console.log("Sync SAM bans to data/bans.json.");
    console.log("MySQL: set SAM_MYSQL_HOST, SAM_MYSQL_USER, SAM_MYSQL_PASSWORD, SAM_MYSQL_DATABASE");
    console.log("SQLite: set SAM_SQLITE_PATH or pass path as first argument (requires better-sqlite3)");
    process.exit(0);
  }

  let bans = await fetchFromMysql();
  if (bans == null) bans = fetchFromSqlite();
  if (bans == null) {
    console.error("No SAM database configured. Set MySQL env vars or SAM_SQLITE_PATH.");
    process.exit(1);
  }

  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
  const nextId = bans.length > 0 ? Math.max(...bans.map((b) => b.id || 0)) + 1 : 1;
  const data = { nextId, bans };
  fs.writeFileSync(bansFile, JSON.stringify(data, null, 2), "utf8");
  console.log("Wrote " + bans.length + " ban(s) to " + bansFile);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
