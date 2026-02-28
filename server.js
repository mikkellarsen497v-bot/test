require("dotenv").config();

const express = require("express");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const https = require("https");
const { GameDig } = require("gamedig");

// Steam OpenID login (set STEAM_API_KEY and BASE_URL in .env; BASE_URL auto-detected on Render via RENDER_EXTERNAL_URL)
let steamAuth = null;
let steamBaseUrl = "";
if (process.env.STEAM_API_KEY) {
  try {
    const SteamAuth = require("node-steam-openid");
    steamBaseUrl = (process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, "");
    steamAuth = new SteamAuth({
      realm: steamBaseUrl,
      returnUrl: `${steamBaseUrl}/api/auth/steam/authenticate`,
      apiKey: process.env.STEAM_API_KEY,
    });
  } catch (e) {
    console.warn("Steam login disabled:", e.message);
  }
}

// Optional: SAM (Simple Admin Mod) MySQL — same DB as Garry's Mod for live bans
let samMysqlPool = null;
if (process.env.SAM_MYSQL_HOST && process.env.SAM_MYSQL_DATABASE) {
  try {
    const mysql = require("mysql2/promise");
    samMysqlPool = mysql.createPool({
      host: process.env.SAM_MYSQL_HOST,
      port: process.env.SAM_MYSQL_PORT ? Number(process.env.SAM_MYSQL_PORT) : 3306,
      user: process.env.SAM_MYSQL_USER || "",
      password: process.env.SAM_MYSQL_PASSWORD || "",
      database: process.env.SAM_MYSQL_DATABASE,
      waitForConnections: true,
      connectionLimit: 4,
    });
  } catch (e) {
    console.warn("SAM MySQL: mysql2 not installed or failed:", e.message);
  }
  if (samMysqlPool) {
    samMysqlPool.query("SELECT 1").then(() => {
      console.log("SAM MySQL: connected to " + (process.env.SAM_MYSQL_HOST || "") + " (bans from your database only)");
    }).catch((e) => {
      console.error("SAM MySQL: connection failed — check .env and that the DB allows this host. Error:", e.message);
    });
  }
}

const app = express();
// Trust first proxy (Render, Nginx, etc.) so req.secure and req.get('host') are correct for cookies
app.set("trust proxy", 1);
const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

// Allow override for persistent volume mounts (Railway, Fly.io, Docker)
const dataDir = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(__dirname, "data");
const staffFile = path.join(dataDir, "staff-applications.jsonl");
const appealFile = path.join(dataDir, "appeals.jsonl");
const usersFile = path.join(dataDir, "users.json");
const sessionsFile = path.join(dataDir, "sessions.json");
const topicsFile = path.join(dataDir, "topics.json");
const repliesFile = path.join(dataDir, "replies.json");
const categoriesFile = path.join(dataDir, "categories.json");
const ranksFile = path.join(dataDir, "ranks.json");
const reactionsFile = path.join(dataDir, "reactions.json");
const reportsFile = path.join(dataDir, "reports.jsonl");
const auditFile = path.join(dataDir, "audit.jsonl");
const lastPostFile = path.join(dataDir, "lastpost.json");
const wordfilterFile = path.join(dataDir, "wordfilter.json");
const reportResolutionsFile = path.join(dataDir, "report-resolutions.json");
const announcementFile = path.join(dataDir, "announcement.json");
const bansFile = path.join(dataDir, "bans.json");
const bansHistoryFile = path.join(dataDir, "bans_history.json");
const ticketsFile = path.join(dataDir, "tickets.jsonl");
const ticketResolutionsFile = path.join(dataDir, "ticket-resolutions.json");

const BANS_HISTORY_MAX = 300;

function ensureDataDir() {
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
}

function readJson(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    const raw = fs.readFileSync(filePath, "utf8");
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function writeJson(filePath, obj) {
  ensureDataDir();
  fs.writeFileSync(filePath, JSON.stringify(obj, null, 2), "utf8");
}

function loadCategories() {
  return readJson(categoriesFile, { nextId: 1, categories: [] });
}

function saveCategories(db) {
  writeJson(categoriesFile, db);
}

function loadRanks() {
  const raw = readJson(ranksFile, { nextId: 1, ranks: [] });
  if (!raw.ranks || !Array.isArray(raw.ranks)) return { nextId: raw.nextId || 1, ranks: [] };
  return {
    nextId: typeof raw.nextId === "number" ? raw.nextId : 1,
    ranks: raw.ranks.map(normalizeRankShape),
  };
}

// Rank level: higher number = more permissions. 1=post, 2=+moderate, 3=+admin
function levelToPermissions(level) {
  const l = Number(level);
  return {
    forums: {
      "*": {
        read: true,
        post: l >= 1,
        moderate: l >= 2,
      },
    },
    site: { accessAdmin: l >= 3 },
  };
}

function permissionsToLevel(perms) {
  if (!perms) return 1;
  const site = perms.site || {};
  if (site.accessAdmin) return 3;
  const wild = (perms.forums && perms.forums["*"]) || {};
  if (wild.moderate) return 2;
  return 1;
}

function normalizeRankShape(r) {
  let level = typeof r.level === "number" && r.level >= 1 && r.level <= 3 ? r.level : null;
  const perms = r.permissions || {};
  if (level == null) level = permissionsToLevel(perms);
  const permissions = levelToPermissions(level);
  return {
    id: r.id,
    name: r.name || "Unnamed",
    badgeUrl: r.badgeUrl || "",
    default: !!r.default,
    level: Math.min(3, Math.max(1, level)),
    permissions,
  };
}

function saveRanks(db) {
  writeJson(ranksFile, db);
}

function ensureDefaultRanks() {
  ensureDataDir();
  const db = loadRanks();
  if (Array.isArray(db.ranks) && db.ranks.length > 0) return;

  // If missing/empty, try seed file
  const seedPath = path.join(__dirname, "data", "ranks.json");
  const seed = readJson(seedPath, null);
  if (seed && Array.isArray(seed.ranks) && seed.ranks.length > 0) {
    saveRanks(seed);
    return;
  }

  saveRanks({
    nextId: 10,
    ranks: [
      { id: 1, name: "Member", badgeUrl: "", default: true, level: 1 },
      { id: 2, name: "Staff", badgeUrl: "", default: false, level: 2 },
      { id: 3, name: "Administrator", badgeUrl: "", default: false, level: 3 },
    ],
  });
}

function ensureDefaultCategories() {
  ensureDataDir();
  const db = loadCategories();
  if (Array.isArray(db.categories) && db.categories.length > 0) return;

  // If missing/empty, write the same structure as data/categories.json seed
  const seedPath = path.join(__dirname, "data", "categories.json");
  const seed = readJson(seedPath, null);
  if (seed && Array.isArray(seed.categories) && seed.categories.length > 0) {
    saveCategories(seed);
    return;
  }

  saveCategories({
    nextId: 100,
    categories: [
      { id: 1, type: "group", title: "Rules & Information", description: "Official updates, server information, and rules." },
      { id: 10, type: "forum", parentId: 1, title: "Announcements & Server Information", description: "Latest server announcements and info." },
      { id: 11, type: "forum", parentId: 1, title: "Community Rules", description: "Global rules, server rules, and forum rules. Read before posting/playing." },
      { id: 2, type: "group", title: "General", description: "Discussion, guides, and suggestions." },
      { id: 20, type: "forum", parentId: 2, title: "Guides & Information", description: "Guides and information for the server." },
      { id: 21, type: "forum", parentId: 2, title: "General Discussion", description: "Talk about anything related to the community/server." },
      { id: 22, type: "forum", parentId: 2, title: "Suggestions", description: "Ideas to improve the server." },
      { id: 3, type: "group", title: "Applications", description: "Apply for roles, trusted status, vendors, and organizations." },
      { id: 30, type: "forum", parentId: 3, title: "Staff Applications", description: "Apply to join the staff team." },
      { id: 31, type: "forum", parentId: 3, title: "Trusted Applications", description: "Apply to be a trusted member." },
      { id: 32, type: "forum", parentId: 3, title: "Criminal Organization Applications", description: "Apply for a criminal organization." },
      { id: 33, type: "forum", parentId: 3, title: "Vendor Applications", description: "Apply to have a vendor/business." },
      { id: 45, type: "forum", parentId: 3, title: "Accepted", description: "Accepted applications (all types)." },
      { id: 46, type: "forum", parentId: 3, title: "Denied", description: "Denied applications (all types)." },
      { id: 4, type: "group", title: "Appeals", description: "Appeal punishments and character actions." },
      { id: 40, type: "forum", parentId: 4, title: "Ban Appeals", description: "Appeal bans or warnings." },
      { id: 41, type: "forum", parentId: 4, title: "PK Appeals", description: "Appeal a character PK decision." },
      { id: 42, type: "forum", parentId: 4, title: "Flag Appeals", description: "Appeal removed flags/permissions." },
      { id: 5, type: "group", title: "Reports", description: "Report players, staff, or bugs." },
      { id: 50, type: "forum", parentId: 5, title: "Staff Reports", description: "Report staff misconduct." },
      { id: 51, type: "forum", parentId: 5, title: "Player Reports", description: "Report players breaking rules." },
      { id: 52, type: "forum", parentId: 5, title: "Bug Reports", description: "Report bugs and issues." }
    ]
  });
}

function nowIso() {
  return new Date().toISOString();
}

function id() {
  // Short, human-friendly ID; not for security.
  return Math.random().toString(36).slice(2, 8).toUpperCase();
}

function secretId(bytes = 24) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function appendJsonl(filePath, obj) {
  ensureDataDir();
  fs.appendFileSync(filePath, JSON.stringify(obj) + "\n", "utf8");
}

function readJsonlLines(filePath, maxLines = 500) {
  if (!fs.existsSync(filePath)) return [];
  const raw = fs.readFileSync(filePath, "utf8");
  const lines = raw.trim().split("\n").filter(Boolean);
  return lines.slice(-maxLines).map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      return null;
    }
  }).filter(Boolean);
}

function appendAuditLog(entry) {
  ensureDataDir();
  const record = {
    at: nowIso(),
    userId: entry.userId || "",
    username: entry.username || "",
    action: entry.action || "",
    targetType: entry.targetType || "",
    targetId: entry.targetId != null ? entry.targetId : "",
    details: entry.details || {},
  };
  appendJsonl(auditFile, record);
}

function loadLastPost() {
  return readJson(lastPostFile, { lastPosts: {} });
}

function saveLastPost(data) {
  writeJson(lastPostFile, data);
}

function loadWordfilter() {
  return readJson(wordfilterFile, { words: [], replacement: "[removed]", blockPost: false });
}

function saveWordfilter(data) {
  writeJson(wordfilterFile, data);
}

function loadReportResolutions() {
  return readJson(reportResolutionsFile, { resolutions: {} });
}

function saveReportResolutions(data) {
  writeJson(reportResolutionsFile, data);
}

function loadTicketResolutions() {
  return readJson(ticketResolutionsFile, { resolutions: {} });
}

function saveTicketResolutions(data) {
  writeJson(ticketResolutionsFile, data);
}

function loadAnnouncement() {
  return readJson(announcementFile, { text: "", link: "", startDate: null, endDate: null, id: null });
}

function saveAnnouncement(data) {
  ensureDataDir();
  if (!data.id) data.id = "announce-" + Date.now();
  writeJson(announcementFile, data);
}

function getCurrentAnnouncement() {
  const a = loadAnnouncement();
  if (!a || !(a.text && a.text.trim())) return null;
  const now = Date.now();
  if (a.startDate) {
    const start = new Date(a.startDate).getTime();
    if (Number.isFinite(start) && now < start) return null;
  }
  if (a.endDate) {
    const end = new Date(a.endDate).getTime();
    if (Number.isFinite(end) && now > end) return null;
  }
  return { id: a.id, text: a.text.trim(), link: (a.link && String(a.link).trim()) || "" };
}

function loadBans() {
  const raw = readJson(bansFile, { nextId: 1, bans: [] });
  if (!raw.bans || !Array.isArray(raw.bans)) return { nextId: raw.nextId || 1, bans: [] };
  return { nextId: typeof raw.nextId === "number" ? raw.nextId : 1, bans: raw.bans };
}

function saveBans(data) {
  writeJson(bansFile, data);
}

function loadBansHistory() {
  const raw = readJson(bansHistoryFile, { lastSeenBySteamId: {}, unbannedHistory: [] });
  return {
    lastSeenBySteamId: raw.lastSeenBySteamId && typeof raw.lastSeenBySteamId === "object" ? raw.lastSeenBySteamId : {},
    unbannedHistory: Array.isArray(raw.unbannedHistory) ? raw.unbannedHistory.slice(0, BANS_HISTORY_MAX) : [],
  };
}

function saveBansHistory(data) {
  ensureDataDir();
  const out = {
    lastSeenBySteamId: data.lastSeenBySteamId || {},
    unbannedHistory: (data.unbannedHistory || []).slice(0, BANS_HISTORY_MAX),
  };
  writeJson(bansHistoryFile, out);
}

// Fetch active bans from SAM MySQL (same schema as SAM addon). Returns array of { date, playerName, steamId, length, staff, reason, server, expiresAt, unbanned }.
async function fetchBansFromSamMysql() {
  if (!samMysqlPool) return null;
  const now = Math.floor(Date.now() / 1000);
  try {
    const [rows] = await samMysqlPool.query(
      `SELECT sam_bans.id, sam_bans.steamid, sam_bans.reason, sam_bans.admin, sam_bans.unban_date,
              IFNULL(p1.name, '') AS name, IFNULL(p2.name, '') AS admin_name
       FROM sam_bans
       LEFT JOIN sam_players AS p1 ON sam_bans.steamid = p1.steamid
       LEFT JOIN sam_players AS p2 ON sam_bans.admin = p2.steamid
       WHERE (sam_bans.unban_date >= ? OR sam_bans.unban_date = 0)
       ORDER BY sam_bans.id DESC`,
      [now]
    );
    if (!Array.isArray(rows)) return null;
    if (rows.length === 0) {
      console.log("SAM MySQL: connected but 0 bans in table. Is the game server using MySQL (same DB)? Check sam_sql_config.lua has MySQL = true.");
    }
    const serverName = process.env.SAM_SERVER_NAME || "Server";
    return rows.map((r) => {
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
    });
  } catch (e) {
    if (e.message && e.message.indexOf("doesn't exist") !== -1) {
      console.log("SAM MySQL: table sam_bans missing. Start your game server once with MySQL = true in sam_sql_config.lua (same DB) so SAM creates the tables.");
      return { tableMissing: true, bans: [] };
    }
    console.error("SAM MySQL fetch failed (bans will show empty until fixed):", e.message);
    return [];
  }
}

function applyWordFilter(body, user, forumId) {
  const wf = loadWordfilter();
  const words = Array.isArray(wf.words) ? wf.words : [];
  if (words.length === 0) return { body, blocked: false };
  if (user && (canAccessAdmin(user) || (forumId != null && canModerateForum(user, forumId)))) return { body, blocked: false };
  let out = body;
  const repl = typeof wf.replacement === "string" ? wf.replacement : "[removed]";
  for (const w of words) {
    if (typeof w !== "string" || !w.trim()) continue;
    const re = new RegExp(w.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
    out = out.replace(re, repl);
  }
  const hadMatch = out !== body;
  if (wf.blockPost && hadMatch) return { body: out, blocked: true };
  return { body: out, blocked: false };
}

function bad(res, message, status = 400) {
  return res.status(status).json({ ok: false, error: message });
}

function clampStr(v, max) {
  if (typeof v !== "string") return "";
  return v.trim().slice(0, max);
}

// Basic JSON + form support
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "200kb" }));

// Very small cookie parser (no dependency)
app.use((req, _res, next) => {
  const header = req.headers.cookie || "";
  const out = {};
  header.split(";").forEach((part) => {
    const idx = part.indexOf("=");
    if (idx === -1) return;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (!k) return;
    out[k] = decodeURIComponent(v);
  });
  req.cookies = out;
  next();
});

// CORS for InfinityFree (frontend on one host, API on Render): set ALLOWED_ORIGIN to your InfinityFree site URL
const allowedOrigins = (process.env.ALLOWED_ORIGIN || "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.length > 0 && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Accept");
    res.setHeader("Access-Control-Max-Age", "86400");
    return res.sendStatus(204);
  }
  next();
});

function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${opts.path || "/"}`);
  if (opts.httpOnly !== false) parts.push("HttpOnly");
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
  if (opts.maxAgeSec != null) parts.push(`Max-Age=${opts.maxAgeSec}`);
  if (opts.secure) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

// When frontend is on another host (e.g. InfinityFree), session cookie must be SameSite=None; Secure so it's sent on cross-site fetch
function sessionCookieOpts(req) {
  const isSecure = req.secure || (req.headers["x-forwarded-proto"] === "https") || process.env.NODE_ENV === "production";
  if (allowedOrigins.length > 0) {
    return { sameSite: "None", maxAgeSec: 604800, secure: true };
  }
  return { sameSite: "Lax", maxAgeSec: 604800, secure: isSecure };
}

function clearCookie(res, name) {
  res.setHeader("Set-Cookie", `${name}=; Path=/; Max-Age=0; HttpOnly`);
}

function loadUsers() {
  return readJson(usersFile, { users: [] });
}

function saveUsers(db) {
  writeJson(usersFile, db);
}

function loadSessions() {
  return readJson(sessionsFile, { sessions: {} });
}

function saveSessions(s) {
  writeJson(sessionsFile, s);
}

function ensureDefaultAdmin() {
  ensureDataDir();
  const db = loadUsers();
  if (db.users.length > 0) return;

  const password = secretId(9);
  const passwordHash = bcrypt.hashSync(password, 10);

  db.users.push({
    id: `USR-${id()}`,
    username: "admin",
    displayName: "Administrator",
    role: "admin",
    rankId: 3,
    passwordHash,
    createdAt: nowIso(),
    disabled: false,
  });
  saveUsers(db);

  fs.writeFileSync(
    path.join(__dirname, "ADMIN_LOGIN.txt"),
    `Project New York - Admin login\n\nUsername: admin\nPassword: ${password}\n\nChange this by editing data/users.json (or tell the agent to add a user manager).\n`,
    "utf8"
  );
}

ensureDefaultAdmin();
ensureDefaultCategories();
ensureDefaultRanks();

function getUserFromSession(req) {
  const sid = req.cookies && req.cookies.pny_session;
  if (!sid) return null;
  const sessions = loadSessions();
  const sess = sessions.sessions[sid];
  if (!sess) return null;
  const users = loadUsers();
  const user = users.users.find((u) => u.id === sess.userId);
  if (!user) return null;
  if (user.disabled) {
    if (user.disabledUntil) {
      const until = new Date(user.disabledUntil).getTime();
      if (Number.isFinite(until) && until < Date.now()) {
        user.disabled = false;
        user.disabledUntil = null;
        user.disabledReason = null;
        saveUsers(users);
      } else return null;
    } else return null;
  }
  const rank = rankForUser(user);
  const role = roleFromRank(rank);
  return { id: user.id, username: user.username, displayName: user.displayName, role, rankId: user.rankId || null };
}

function requireAuth(req, res, next) {
  const user = getUserFromSession(req);
  if (!user) return bad(res, "You must be signed in.", 401);
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const user = getUserFromSession(req);
  if (!user) return bad(res, "You must be signed in.", 401);
  if (!canAccessAdmin(user)) return bad(res, "Admin only.", 403);
  req.user = user;
  next();
}

function requireStaff(req, res, next) {
  const user = getUserFromSession(req);
  if (!user) return bad(res, "You must be signed in.", 401);
  const role = user.role || "";
  if (role !== "staff" && role !== "admin") return bad(res, "Staff only.", 403);
  req.user = user;
  next();
}

function isValidUsername(u) {
  return /^[a-zA-Z0-9_]{3,20}$/.test(u);
}

function isValidRole(r) {
  return r === "member" || r === "staff" || r === "admin";
}

function roleFromRank(rank) {
  if (!rank || !rank.permissions) return "member";
  const site = rank.permissions.site || {};
  if (site.accessAdmin) return "admin";
  const forums = rank.permissions.forums || {};
  const wild = forums["*"] || {};
  if (wild.moderate) return "staff";
  return "member";
}

function rankForUser(user) {
  if (!user) return null;
  const db = loadRanks();
  if (!db.ranks || db.ranks.length === 0) return null;
  const defaultRank = db.ranks.find((r) => r.default) || db.ranks[0];
  const rid = user.rankId != null && user.rankId !== "" && Number.isFinite(Number(user.rankId))
    ? Number(user.rankId)
    : (defaultRank && defaultRank.id);
  let rank = db.ranks.find((r) => r.id === rid) || defaultRank || null;
  // Legacy: user has role "admin" but their rank doesn't grant admin → use first admin rank
  if (user.role === "admin" && rank && !(rank.permissions && rank.permissions.site && rank.permissions.site.accessAdmin)) {
    const adminRank = db.ranks.find((r) => r.permissions && r.permissions.site && r.permissions.site.accessAdmin);
    if (adminRank) rank = adminRank;
  }
  return rank;
}

function canAccessAdmin(user) {
  if (!user) return false;
  const rank = rankForUser(user);
  return !!(rank && rank.permissions && rank.permissions.site && rank.permissions.site.accessAdmin);
}

function forumPermForRank(rank, forumId) {
  const forums = (rank && rank.permissions && rank.permissions.forums) || {};
  const base = { read: true, post: true, moderate: false };
  const wildcard = forums["*"] || null;
  const specific = forums[String(forumId)] || null;
  return { ...base, ...(wildcard || {}), ...(specific || {}) };
}

function canReadForum(user, forumId) {
  if (!forumId) return true;
  if (!user) return true;
  if (canAccessAdmin(user)) return true;
  const rank = rankForUser(user);
  return !!forumPermForRank(rank, forumId).read;
}

function canPostForum(user, forumId) {
  if (!user) return false;
  if (canAccessAdmin(user)) return true;
  const rank = rankForUser(user);
  return !!forumPermForRank(rank, forumId).post;
}

function canModerateForum(user, forumId) {
  if (!user) return false;
  if (canAccessAdmin(user)) return true;
  const rank = rankForUser(user);
  return !!forumPermForRank(rank, forumId).moderate;
}

function loadTopics() {
  return readJson(topicsFile, { nextId: 1, topics: [] });
}

function saveTopics(db) {
  writeJson(topicsFile, db);
}

function createTopic({ category, title, body, author, tags }) {
  const db = loadTopics();
  const cats = loadCategories();
  const catIdNum = typeof category === "number" ? category : Number(category);
  const catObj = cats.categories.find((c) => c.id === catIdNum && c.type === "forum");
  const categoryId = catObj ? catObj.id : null;
  const categoryTitle = catObj ? catObj.title : String(category);

  const tagsList = Array.isArray(tags) ? tags.slice(0, 5) : [];
  const normalizedTags = tagsList
    .map((t) => String(t).trim().slice(0, 20))
    .filter(Boolean);

  const topic = {
    id: db.nextId++,
    categoryId,
    categoryTitle,
    title,
    body,
    author,
    tags: normalizedTags,
    pinnedAt: null,
    lockedAt: null,
    lockedBy: null,
    deletedAt: null,
    deletedBy: null,
    updatedAt: null,
    status: "open",
    createdAt: nowIso(),
  };
  db.topics.unshift(topic);
  saveTopics(db);
  return topic;
}

function loadReplies() {
  return readJson(repliesFile, { nextId: 1, replies: [] });
}

function saveReplies(db) {
  writeJson(repliesFile, db);
}

function loadReactions() {
  return readJson(reactionsFile, { nextId: 1, reactions: [] });
}

function saveReactions(db) {
  writeJson(reactionsFile, db);
}

const ALLOWED_EMOJIS = new Set(["like", "heart"]);

// Basic in-memory rate limit per IP per route
const buckets = new Map();
function rateLimit(key, maxPerMinute) {
  return (req, res, next) => {
    const ip = req.ip || req.headers["x-forwarded-for"] || "unknown";
    const bucketKey = `${key}:${ip}`;
    const now = Date.now();
    const windowMs = 60_000;
    const entry = buckets.get(bucketKey) || { start: now, count: 0 };
    if (now - entry.start > windowMs) {
      entry.start = now;
      entry.count = 0;
    }
    entry.count += 1;
    buckets.set(bucketKey, entry);
    if (entry.count > maxPerMinute) return bad(res, "Too many requests. Try again later.", 429);
    next();
  };
}

// Brute-force protection: lock out IP after too many failed logins
const loginFailures = new Map();
const LOGIN_MAX_FAILURES = 5;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes

function getClientIp(req) {
  return (req.ip || (req.headers["x-forwarded-for"] && req.headers["x-forwarded-for"].split(",")[0].trim()) || "unknown");
}

function isLoginBlocked(req) {
  const ip = getClientIp(req);
  const entry = loginFailures.get(ip);
  if (!entry) return false;
  if (Date.now() - entry.lockUntil > 0) {
    loginFailures.delete(ip);
    return false;
  }
  return true;
}

function recordLoginFailure(req) {
  const ip = getClientIp(req);
  const now = Date.now();
  const entry = loginFailures.get(ip) || { count: 0, firstAt: now, lockUntil: 0 };
  entry.count += 1;
  entry.firstAt = entry.firstAt || now;
  if (entry.count >= LOGIN_MAX_FAILURES) {
    entry.lockUntil = now + LOGIN_LOCKOUT_MS;
  }
  loginFailures.set(ip, entry);
}

function clearLoginFailures(req) {
  loginFailures.delete(getClientIp(req));
}

function getProfileFields(user) {
  if (!user) return {};
  return {
    avatarUrl: typeof user.avatarUrl === "string" ? user.avatarUrl.slice(0, 500000) : "",
    coverUrl: typeof user.coverUrl === "string" ? user.coverUrl.slice(0, 500000) : "",
    postbitCoverUrl: typeof user.postbitCoverUrl === "string" ? user.postbitCoverUrl.slice(0, 500000) : "",
    profileTitle: typeof user.profileTitle === "string" ? user.profileTitle.slice(0, 100) : "",
    profileBio: typeof user.profileBio === "string" ? user.profileBio.slice(0, 3000) : "",
    profileColor: typeof user.profileColor === "string" ? user.profileColor.slice(0, 20) : "",
  };
}

function getAuthorAvatar(userId) {
  if (!userId) return "";
  const users = loadUsers();
  const u = users.users.find((x) => x.id === userId);
  return u && typeof u.avatarUrl === "string" ? u.avatarUrl.slice(0, 500000) : "";
}

app.get("/api/me", (req, res) => {
  const sessUser = getUserFromSession(req);
  if (!sessUser) return res.json({ ok: true, user: null });
  const users = loadUsers();
  const full = users.users.find((u) => u.id === sessUser.id);
  if (!full) return res.json({ ok: true, user: null });
  const rank = rankForUser(full);
  const role = roleFromRank(rank);
  res.json({
    ok: true,
    user: {
      id: full.id,
      username: full.username,
      displayName: full.displayName,
      role,
      rankId: full.rankId || null,
      createdAt: full.createdAt,
      lastReadAllAt: full.lastReadAllAt || null,
      watchedTopicIds: Array.isArray(full.watchedTopicIds) ? full.watchedTopicIds : [],
      ...getProfileFields(full),
    },
  });
});

app.get("/api/announcement", (req, res) => {
  const a = getCurrentAnnouncement();
  res.json({ ok: true, announcement: a });
});

app.get("/api/admin/announcement", requireAdmin, (req, res) => {
  const a = loadAnnouncement();
  res.json({ ok: true, announcement: a });
});

app.put("/api/admin/announcement", requireAdmin, rateLimit("admin_announcement", 20), (req, res) => {
  const text = typeof req.body.text === "string" ? req.body.text.trim() : "";
  const link = typeof req.body.link === "string" ? req.body.link.trim() : "";
  const startDate = req.body.startDate && String(req.body.startDate).trim() ? String(req.body.startDate).trim() : null;
  const endDate = req.body.endDate && String(req.body.endDate).trim() ? String(req.body.endDate).trim() : null;
  const current = loadAnnouncement();
  const data = { ...current, text, link, startDate, endDate };
  if (!data.id) data.id = "announce-" + Date.now();
  saveAnnouncement(data);
  res.json({ ok: true, announcement: getCurrentAnnouncement() || data });
});

app.post("/api/me/mark-all-read", requireAuth, (req, res) => {
  const users = loadUsers();
  const u = users.users.find((x) => x.id === req.user.id);
  if (!u) return bad(res, "User not found.", 404);
  u.lastReadAllAt = nowIso();
  saveUsers(users);
  res.json({ ok: true, lastReadAllAt: u.lastReadAllAt });
});

// Public bans list — from YOUR database only. Keeps unbanned as history so they "stay" on the site.
app.get("/api/bans", async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const pageSize = Math.min(100, Math.max(10, parseInt(req.query.limit, 10) || 25));
  let bans = [];
  let source = "json";
  let tableMissing = false;
  if (samMysqlPool) {
    source = "mysql";
    const fromDb = await fetchBansFromSamMysql();
    if (fromDb && fromDb.tableMissing) {
      tableMissing = true;
      bans = [];
    } else {
      const currentBans = Array.isArray(fromDb) ? fromDb : [];
      const history = loadBansHistory();
      const nowIso = new Date().toISOString();
      const currentBySteamId = {};
      for (const b of currentBans) {
        if (b.steamId) {
          const firstSeenAt = (history.lastSeenBySteamId && history.lastSeenBySteamId[b.steamId] && history.lastSeenBySteamId[b.steamId].firstSeenAt) || nowIso;
          currentBySteamId[b.steamId] = { ...b, firstSeenAt };
        }
      }
      const unbannedHistory = [...(history.unbannedHistory || [])];
      for (const steamid of Object.keys(history.lastSeenBySteamId || {})) {
        if (!currentBySteamId[steamid]) {
          const prev = history.lastSeenBySteamId[steamid];
          if (prev && prev.steamId) {
            unbannedHistory.unshift({
              ...prev,
              date: prev.firstSeenAt || prev.date,
              unbanned: true,
              unbannedAt: nowIso,
              length: (prev.length || "—") + " (Unbanned)",
            });
          }
        }
      }
      saveBansHistory({
        lastSeenBySteamId: currentBySteamId,
        unbannedHistory: unbannedHistory.slice(0, BANS_HISTORY_MAX),
      });
      const activeWithDate = currentBans.map((b) => ({
        ...b,
        date: (currentBySteamId[b.steamId] && currentBySteamId[b.steamId].firstSeenAt) || null,
      }));
      bans = [...activeWithDate, ...unbannedHistory];
    }
  } else {
    const db = loadBans();
    bans = Array.isArray(db.bans) ? db.bans : [];
  }
  const total = bans.length;
  const start = (page - 1) * pageSize;
  const slice = bans.slice(start, start + pageSize);
  const payload = { ok: true, bans: slice, total, page, pageSize };
  if (req.query.status === "1") {
    payload.source = source;
    if (tableMissing) payload.tableMissing = true;
  }
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.json(payload);
});

// Admin: remove a ban from the database. Ban stays on site as "Unbanned" in history.
app.post("/api/admin/bans/unban", requireAdmin, async (req, res) => {
  const steamid = typeof req.body.steamid === "string" ? req.body.steamid.trim() : "";
  if (!steamid) return bad(res, "steamid required.");
  if (!samMysqlPool) return bad(res, "Bans are not stored in MySQL; cannot unban from here.", 400);
  try {
    const [rows] = await samMysqlPool.query(
      `SELECT sam_bans.steamid, sam_bans.reason, sam_bans.admin, sam_bans.unban_date,
              IFNULL(p1.name, '') AS name, IFNULL(p2.name, '') AS admin_name
       FROM sam_bans
       LEFT JOIN sam_players AS p1 ON sam_bans.steamid = p1.steamid
       LEFT JOIN sam_players AS p2 ON sam_bans.admin = p2.steamid
       WHERE sam_bans.steamid = ?`,
      [steamid]
    );
    const history = loadBansHistory();
    const unbannedHistory = [...(history.unbannedHistory || [])];
    if (rows && rows[0]) {
      const r = rows[0];
      const serverName = process.env.SAM_SERVER_NAME || "Server";
      const unbannedAt = new Date().toISOString();
      const prevSeen = (history.lastSeenBySteamId && history.lastSeenBySteamId[steamid]) || {};
      unbannedHistory.unshift({
        playerName: (r.name && String(r.name).trim()) || null,
        steamId: r.steamid || "",
        length: "Unbanned",
        staff: (r.admin_name && String(r.admin_name).trim()) || (r.admin === "Console" ? "Console" : r.admin || ""),
        reason: r.reason || "",
        server: serverName,
        unbanned: true,
        unbannedAt,
        date: prevSeen.firstSeenAt || unbannedAt,
      });
    }
    const [result] = await samMysqlPool.query("DELETE FROM sam_bans WHERE steamid = ?", [steamid]);
    const deleted = result && result.affectedRows;
    if (deleted) {
      const bySteamId = { ...(history.lastSeenBySteamId || {}) };
      delete bySteamId[steamid];
      saveBansHistory({ lastSeenBySteamId: bySteamId, unbannedHistory: unbannedHistory.slice(0, BANS_HISTORY_MAX) });
    }
    res.json({ ok: true, removed: !!deleted });
  } catch (e) {
    console.error("SAM MySQL unban failed:", e.message);
    return bad(res, "Database error.", 500);
  }
});

app.get("/api/ranks", (_req, res) => {
  const db = loadRanks();
  res.json({
    ok: true,
    ranks: db.ranks.map((r) => ({ id: r.id, name: r.name, badgeUrl: r.badgeUrl || "" })),
  });
});

// Live game server status (GMod at 193.243.190.19:27015)
const GAME_SERVER = { host: "193.243.190.19", port: 27015 };
// Fallback: many GMod servers don't expose host_uptime in rules; track "seen up since" locally
let gameServerUpSince = null;
function formatUptime(seconds) {
  if (seconds == null || !Number.isFinite(seconds) || seconds < 0) return null;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m`;
  return "< 1m";
}
app.get("/api/server-status", (req, res) => {
  GameDig.query({
    type: "garrysmod",
    host: GAME_SERVER.host,
    port: GAME_SERVER.port,
    requestRules: true,
  })
    .then((state) => {
      const players = typeof state.numplayers === "number" ? state.numplayers : (Array.isArray(state.players) ? state.players.length : 0);
      const maxPlayers = state.maxplayers ?? 128;
      const rules = state.raw && state.raw.rules;
      const rawUptime = rules && (rules.host_uptime ?? rules.host_uptime_seconds);
      let uptimeSeconds = rawUptime != null && rawUptime !== "" ? parseInt(String(rawUptime), 10) : null;
      if (!Number.isFinite(uptimeSeconds)) {
        if (gameServerUpSince == null) gameServerUpSince = Date.now();
        uptimeSeconds = Math.floor((Date.now() - gameServerUpSince) / 1000);
      }
      res.json({
        ok: true,
        online: true,
        players: Math.min(players, maxPlayers),
        maxPlayers,
        map: state.map || null,
        name: state.name || null,
        uptimeSeconds: Number.isFinite(uptimeSeconds) ? uptimeSeconds : null,
        uptimeFormatted: formatUptime(uptimeSeconds),
      });
    })
    .catch((err) => {
      gameServerUpSince = null;
      console.error("Server status query error:", err.message);
      res.json({
        ok: true,
        online: false,
        players: null,
        maxPlayers: 128,
        map: null,
        name: null,
        uptimeSeconds: null,
        uptimeFormatted: null,
      });
    });
});

// Discord invite stats (approximate member count and online count; no bot token required)
const DISCORD_INVITE_CODE = "qBejzcjt";
app.get("/api/discord-stats", (req, res) => {
  const url = `https://discord.com/api/v10/invites/${DISCORD_INVITE_CODE}?with_counts=true`;
  https
    .get(url, (apiRes) => {
      let body = "";
      apiRes.on("data", (chunk) => { body += chunk; });
      apiRes.on("end", () => {
        try {
          const data = JSON.parse(body);
          const members = data.approximate_member_count;
          const online = data.approximate_presence_count;
          if (typeof members === "number" && typeof online === "number") {
            return res.json({ ok: true, members, online });
          }
        } catch (_) {}
        res.json({ ok: false, members: null, online: null });
      });
    })
    .on("error", () => res.json({ ok: false, members: null, online: null }));
});

// Public who's-online counts for forums sidebar (members = logged-in sessions; no guest tracking)
app.get("/api/online", (req, res) => {
  const sessions = loadSessions();
  const users = loadUsers();
  let members = 0;
  for (const sid of Object.keys(sessions.sessions || {})) {
    const sess = sessions.sessions[sid];
    if (sess && sess.userId) {
      const user = users.users.find((u) => u.id === sess.userId);
      if (user && !user.disabled) members++;
    }
  }
  res.json({ ok: true, members, anonymous: 0, guests: 0 });
});

app.get("/api/staff", (req, res) => {
  try {
    const usersDb = loadUsers();
    const users = Array.isArray(usersDb.users) ? usersDb.users : [];
    const staff = users
      .filter((u) => !u.disabled)
      .map((u) => {
        const rank = rankForUser(u);
        const role = rank ? roleFromRank(rank) : "member";
        return { user: u, rank, role };
      })
      .filter(({ role }) => role === "staff" || role === "admin");
    res.json({
      ok: true,
      staff: staff.map(({ user, rank }) => ({
        id: user.id,
        username: user.username,
        displayName: user.displayName,
        role: user.role,
        rankId: user.rankId || null,
        rankName: rank ? rank.name : "Member",
      })),
    });
  } catch (err) {
    console.error("/api/staff error:", err);
    res.status(500).json({ ok: false, error: "Server error loading staff." });
  }
});

// Rate-limit all admin API access (per IP) to slow brute-force and abuse
app.use("/api/admin", rateLimit("admin_api", 80));

app.get("/api/admin/ranks", requireAdmin, (_req, res) => {
  const db = loadRanks();
  res.json({ ok: true, nextId: db.nextId, ranks: db.ranks || [] });
});

app.post("/api/admin/ranks", requireAdmin, rateLimit("admin_rank_create", 40), (req, res) => {
  const name = clampStr(req.body.name, 80);
  const badgeUrl = clampStr(req.body.badgeUrl || "", 200);
  const level = Math.min(3, Math.max(1, Number(req.body.level) || 1));
  const isDefault = !!req.body.default;

  if (!name) return bad(res, "Name is required.");

  const db = loadRanks();
  const rank = {
    id: db.nextId++,
    name,
    badgeUrl,
    default: isDefault,
    level,
    permissions: levelToPermissions(level),
  };

  if (isDefault) {
    db.ranks.forEach((r) => {
      r.default = false;
    });
  }

  db.ranks.push(rank);
  saveRanks(db);
  res.json({ ok: true, id: rank.id });
});

// Alternate create endpoint (same as POST /api/admin/ranks)
app.post("/api/admin/ranks/create", requireAdmin, rateLimit("admin_rank_create", 40), (req, res) => {
  const name = clampStr(req.body.name, 80);
  const badgeUrl = clampStr(req.body.badgeUrl || "", 200);
  const level = Math.min(3, Math.max(1, Number(req.body.level) || 1));
  const isDefault = !!req.body.default;

  if (!name) return bad(res, "Name is required.");

  const db = loadRanks();
  const rank = {
    id: db.nextId++,
    name,
    badgeUrl,
    default: isDefault,
    level,
    permissions: levelToPermissions(level),
  };

  if (isDefault) {
    db.ranks.forEach((r) => {
      r.default = false;
    });
  }

  db.ranks.push(rank);
  saveRanks(db);
  res.json({ ok: true, id: rank.id });
});

app.patch("/api/admin/ranks/:id", requireAdmin, rateLimit("admin_rank_patch", 80), (req, res) => {
  const idNum = Number(req.params.id);
  if (!Number.isFinite(idNum)) return bad(res, "Invalid rank id.");
  const db = loadRanks();
  const rank = db.ranks.find((r) => r.id === idNum);
  if (!rank) return bad(res, "Rank not found.", 404);

  const name = clampStr(req.body.name || "", 80);
  const badgeUrl = clampStr(req.body.badgeUrl || "", 200);
  const levelReq = req.body.level != null ? Number(req.body.level) : null;
  const isDefault = typeof req.body.default === "boolean" ? !!req.body.default : undefined;

  if (name) rank.name = name;
  if (badgeUrl !== undefined) rank.badgeUrl = badgeUrl;

  if (levelReq >= 1 && levelReq <= 3) {
    rank.level = levelReq;
    rank.permissions = levelToPermissions(levelReq);
  }

  if (typeof isDefault === "boolean") {
    if (isDefault) {
      db.ranks.forEach((r) => {
        r.default = false;
      });
      rank.default = true;
    } else {
      rank.default = false;
      if (!db.ranks.some((r) => r.default)) {
        const first = db.ranks[0];
        if (first) first.default = true;
      }
    }
  }

  saveRanks(db);
  res.json({ ok: true });
});

app.delete("/api/admin/ranks/:id", requireAdmin, rateLimit("admin_rank_delete", 40), (req, res) => {
  const idNum = Number(req.params.id);
  if (!Number.isFinite(idNum)) return bad(res, "Invalid rank id.");

  const db = loadRanks();
  const idx = db.ranks.findIndex((r) => r.id === idNum);
  if (idx === -1) return bad(res, "Rank not found.", 404);
  if (db.ranks.length <= 1) return bad(res, "Cannot delete the last rank.", 400);

  // prevent delete default
  if (db.ranks[idx].default) return bad(res, "Cannot delete the default rank.", 400);

  // prevent delete if any user is using it
  const users = loadUsers();
  const inUse = users.users.some((u) => u.rankId === idNum);
  if (inUse) return bad(res, "Rank is in use by at least one user.", 400);

  db.ranks.splice(idx, 1);
  saveRanks(db);
  res.json({ ok: true });
});

app.get("/api/users/by-username/:username", (req, res) => {
  const username = clampStr(req.params.username, 40).toLowerCase();
  const db = loadUsers();
  const user = db.users.find((u) => String(u.username || "").toLowerCase() === username);
  if (!user || user.disabled) return bad(res, "User not found.", 404);
  res.json({ ok: true, id: user.id });
});

app.get("/api/users/:id", (req, res) => {
  const id = clampStr(req.params.id, 60);
  const db = loadUsers();
  const user = db.users.find((u) => u.id === id);
  if (!user || user.disabled) return bad(res, "User not found.", 404);
  const rank = loadRanks().ranks.find((r) => r.id === (user.rankId || 1)) || null;
  const profile = getProfileFields(user);
  const viewer = getUserFromSession(req);
  const warnings = Array.isArray(user.warnings) ? user.warnings : [];
  const showWarningsList = viewer && (canAccessAdmin(viewer) || (viewer.role === "staff"));
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.json({
    ok: true,
    user: {
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      role: user.role,
      rank: rank ? { id: rank.id, name: rank.name, badgeUrl: rank.badgeUrl || "" } : null,
      createdAt: user.createdAt,
      warningsCount: warnings.length,
      warnings: showWarningsList ? warnings : undefined,
      avatarUrl: profile.avatarUrl || "",
      coverUrl: profile.coverUrl || "",
      postbitCoverUrl: profile.postbitCoverUrl || "",
      profileTitle: profile.profileTitle || "",
      profileBio: profile.profileBio || "",
      profileColor: profile.profileColor || "",
    },
  });
});

app.get("/api/users/:id/topics", (req, res) => {
  const uid = clampStr(req.params.id, 60);
  const users = loadUsers();
  const u = users.users.find((x) => x.id === uid);
  if (!u || u.disabled) return bad(res, "User not found.", 404);

  const viewer = getUserFromSession(req);
  const db = loadTopics();
  const topics = db.topics
    .filter((t) => !t.deletedAt)
    .filter((t) => t.author && t.author.id === uid)
    .filter((t) => canReadForum(viewer, t.categoryId))
    .slice(0, 200);
  res.json({ ok: true, topics });
});

app.get("/api/users/:id/stats", (req, res) => {
  const uid = clampStr(req.params.id, 60);
  const users = loadUsers();
  const u = users.users.find((x) => x.id === uid);
  if (!u || u.disabled) return bad(res, "User not found.", 404);

  const viewer = getUserFromSession(req);
  const tdb = loadTopics();
  const rdb = loadReplies();

  const topicsCount = tdb.topics.filter((t) => !t.deletedAt && t.author && t.author.id === uid && canReadForum(viewer, t.categoryId)).length;
  const repliesCount = rdb.replies.filter((r) => !r.deletedAt && r.author && r.author.id === uid).length;

  res.json({ ok: true, stats: { topicsCount, repliesCount } });
});

app.patch("/api/me/profile", requireAuth, rateLimit("profile", 30), (req, res) => {
  const db = loadUsers();
  const user = db.users.find((u) => u.id === req.user.id);
  if (!user) return bad(res, "User not found.", 404);

  if (req.body.avatarUrl !== undefined) user.avatarUrl = typeof req.body.avatarUrl === "string" ? req.body.avatarUrl.trim().slice(0, 500000) : "";
  if (req.body.coverUrl !== undefined) user.coverUrl = typeof req.body.coverUrl === "string" ? req.body.coverUrl.trim().slice(0, 500000) : "";
  if (req.body.postbitCoverUrl !== undefined) user.postbitCoverUrl = typeof req.body.postbitCoverUrl === "string" ? req.body.postbitCoverUrl.trim().slice(0, 500000) : "";
  if (req.body.profileTitle !== undefined) user.profileTitle = clampStr(req.body.profileTitle, 100);
  if (req.body.profileBio !== undefined) user.profileBio = typeof req.body.profileBio === "string" ? req.body.profileBio.slice(0, 3000) : "";
  if (req.body.profileColor !== undefined) user.profileColor = clampStr(req.body.profileColor, 20);

  try {
    saveUsers(db);
  } catch (err) {
    console.error("Save users error:", err);
    return bad(res, "Failed to save profile.", 500);
  }
  res.json({ ok: true });
});

// --- Steam login ---
const frontendUrl = (process.env.FRONTEND_URL || process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || "").replace(/\/$/, "");
const steamRedirect = (path) => (frontendUrl ? frontendUrl + (path.startsWith("/") ? path : "/" + path) : path.startsWith("/") ? path : "/" + path);

app.get("/api/auth/steam", rateLimit("login", 10), (req, res) => {
  if (!steamAuth) return res.redirect(302, steamRedirect("/signin.html?error=steam_not_configured"));
  const nextPath = clampStr(req.query.next, 200) || "index.html";
  const isSecure = req.secure || (req.headers["x-forwarded-proto"] === "https") || process.env.NODE_ENV === "production";
  setCookie(res, "pny_steam_next", nextPath, { sameSite: "Lax", maxAgeSec: 300, secure: isSecure, httpOnly: true });
  steamAuth.getRedirectUrl().then((url) => res.redirect(302, url)).catch((err) => {
    console.error("Steam redirect error:", err);
    res.redirect(302, steamRedirect("/signin.html?error=steam_error"));
  });
});

app.get("/api/auth/steam/authenticate", rateLimit("login", 10), async (req, res) => {
  if (!steamAuth) return res.redirect(302, steamRedirect("/signin.html?error=steam_not_configured"));
  const nextPath = (req.cookies && req.cookies.pny_steam_next) ? req.cookies.pny_steam_next.replace(/[^a-zA-Z0-9_.-]/g, "") || "index.html" : "index.html";
  const isSecure = req.secure || (req.headers["x-forwarded-proto"] === "https") || process.env.NODE_ENV === "production";
  const clearNextCookie = () => { res.append("Set-Cookie", "pny_steam_next=; Path=/; Max-Age=0; HttpOnly"); };
  try {
    // Use request's full URL as return URL so OpenID verification passes behind proxies (Steam adds query params to callback)
    const fullReturnUrl = `${req.protocol}://${req.get("host") || "localhost"}${req.originalUrl || req.url}`;
    const openid = require("openid");
    const rp = new openid.RelyingParty(fullReturnUrl, steamBaseUrl, true, true, []);
    const steamUser = await new Promise((resolve, reject) => {
      rp.verifyAssertion(req, (err, result) => {
        if (err) return reject(new Error(err.message || String(err)));
        if (!result || !result.authenticated) return reject(new Error("Failed to authenticate user."));
        if (!/^https?:\/\/steamcommunity\.com\/openid\/id\/\d+$/.test(result.claimedIdentifier)) return reject(new Error("Claimed identity is not valid."));
        steamAuth.fetchIdentifier(result.claimedIdentifier).then(resolve).catch(reject);
      });
    });
    const steamId = String(steamUser.steamid || "").trim();
    const displayName = clampStr(steamUser.name || steamUser.username || "Steam User", 40);
    if (!steamId) {
      clearNextCookie();
      return res.redirect(302, steamRedirect("/signin.html?error=steam_no_id"));
    }
    const db = loadUsers();
    let user = db.users.find((u) => u.steamId === steamId);
    if (!user) {
      const ranksDb = loadRanks();
      const defaultRank = ranksDb.ranks.find((r) => r.default) || ranksDb.ranks[0];
      const defaultRankId = defaultRank ? defaultRank.id : 1;
      const username = "steam_" + steamId;
      user = {
        id: `USR-${id()}`,
        username,
        displayName,
        role: roleFromRank(defaultRank),
        rankId: defaultRankId,
        passwordHash: bcrypt.hashSync(secretId(32), 10),
        steamId,
        createdAt: nowIso(),
        disabled: false,
      };
      db.users.push(user);
      saveUsers(db);
    }
    if (user.disabled) {
      clearNextCookie();
      return res.redirect(302, steamRedirect("/signin.html?error=account_disabled"));
    }
    clearLoginFailures(req);
    const sid = secretId(24);
    const sessions = loadSessions();
    sessions.sessions[sid] = { userId: user.id, createdAt: nowIso() };
    saveSessions(sessions);
    setCookie(res, "pny_session", sid, sessionCookieOpts(req));
    clearNextCookie();
    const targetPath = nextPath.startsWith("/") ? nextPath.slice(1) : nextPath;
    console.log("Steam login success:", user.username, "->", targetPath);
    res.redirect(302, steamRedirect("/" + targetPath));
  } catch (err) {
    const errMsg = err && (err.message || String(err));
    console.error("Steam authenticate error:", errMsg, err);
    clearNextCookie();
    res.redirect(302, steamRedirect("/signin.html?error=steam_failed"));
  }
});

app.post("/api/login", rateLimit("login", 5), (req, res) => {
  if (isLoginBlocked(req)) return bad(res, "Too many failed login attempts. Try again in 15 minutes.", 429);

  const username = clampStr(req.body.username, 40).toLowerCase();
  const password = clampStr(req.body.password, 200);
  if (!username || !password) return bad(res, "Username and password are required.");

  const db = loadUsers();
  const user = db.users.find((u) => String(u.username).toLowerCase() === username);
  if (!user) {
    recordLoginFailure(req);
    return bad(res, "Invalid username or password.", 401);
  }
  if (user.disabled) return bad(res, "This account is disabled.", 403);
  if (!bcrypt.compareSync(password, user.passwordHash)) {
    recordLoginFailure(req);
    return bad(res, "Invalid username or password.", 401);
  }

  clearLoginFailures(req);
  const sid = secretId(24);
  const sessions = loadSessions();
  sessions.sessions[sid] = { userId: user.id, createdAt: nowIso() };
  saveSessions(sessions);

  setCookie(res, "pny_session", sid, sessionCookieOpts(req));
  res.json({
    ok: true,
    user: { id: user.id, username: user.username, displayName: user.displayName, role: user.role, rankId: user.rankId || null },
  });
});

app.post("/api/signup", rateLimit("signup", 6), (req, res) => {
  const usernameRaw = clampStr(req.body.username, 40);
  const username = usernameRaw.toLowerCase();
  const displayName = clampStr(req.body.displayName, 40) || usernameRaw;
  const password = clampStr(req.body.password, 200);

  if (!isValidUsername(usernameRaw)) return bad(res, "Username must be 3–20 chars: letters/numbers/underscore only.");
  if (!password || password.length < 6) return bad(res, "Password must be at least 6 characters.");

  const db = loadUsers();
  const exists = db.users.some((u) => String(u.username).toLowerCase() === username);
  if (exists) return bad(res, "That username is already taken.", 409);

  const ranksDb = loadRanks();
  const defaultRank = ranksDb.ranks.find((r) => r.default) || ranksDb.ranks[0];
  const defaultRankId = defaultRank ? defaultRank.id : 1;

  const user = {
    id: `USR-${id()}`,
    username,
    displayName,
    role: roleFromRank(defaultRank),
    rankId: defaultRankId,
    passwordHash: bcrypt.hashSync(password, 10),
    createdAt: nowIso(),
    disabled: false,
  };
  db.users.push(user);
  saveUsers(db);

  // Auto-login after signup
  const sid = secretId(24);
  const sessions = loadSessions();
  sessions.sessions[sid] = { userId: user.id, createdAt: nowIso() };
  saveSessions(sessions);
  setCookie(res, "pny_session", sid, sessionCookieOpts(req));

  res.json({ ok: true, user: { id: user.id, username: user.username, displayName: user.displayName, role: user.role, rankId: user.rankId || null } });
});

app.get("/api/admin/users", requireAdmin, (req, res) => {
  const db = loadUsers();
  res.json({
    ok: true,
    users: db.users.map((u) => ({
      id: u.id,
      username: u.username,
      displayName: u.displayName,
      role: u.role,
      rankId: u.rankId || null,
      createdAt: u.createdAt,
      disabled: !!u.disabled,
      disabledReason: u.disabledReason || null,
      disabledUntil: u.disabledUntil || null,
      staffNotes: u.staffNotes || null,
      warningsCount: Array.isArray(u.warnings) ? u.warnings.length : 0,
    })),
  });
});

app.get("/api/admin/online", requireAdmin, (req, res) => {
  const sessions = loadSessions();
  const users = loadUsers();
  const ranksDb = loadRanks();
  const userIdToLatest = {};
  for (const sid of Object.keys(sessions.sessions || {})) {
    const sess = sessions.sessions[sid];
    if (!sess || !sess.userId) continue;
    const t = sess.createdAt ? new Date(sess.createdAt).getTime() : 0;
    if (!userIdToLatest[sess.userId] || userIdToLatest[sess.userId] < t) {
      userIdToLatest[sess.userId] = t;
    }
  }
  const online = [];
  for (const userId of Object.keys(userIdToLatest)) {
    const user = users.users.find((u) => u.id === userId);
    if (!user || user.disabled) continue;
    const rank = rankForUser(user);
    online.push({
      id: user.id,
      username: user.username,
      displayName: user.displayName || user.username,
      rankName: rank ? rank.name : "—",
      lastActive: userIdToLatest[userId] ? new Date(userIdToLatest[userId]).toISOString() : null,
    });
  }
  online.sort((a, b) => (b.lastActive || "").localeCompare(a.lastActive || ""));
  res.json({ ok: true, online });
});

app.post("/api/admin/users", requireAdmin, rateLimit("admin_create_user", 20), (req, res) => {
  const usernameRaw = clampStr(req.body.username, 40);
  const username = usernameRaw.toLowerCase();
  const displayName = clampStr(req.body.displayName, 40) || usernameRaw;
  const rankId = req.body.rankId != null ? Number(req.body.rankId) : null;
  const password = clampStr(req.body.password, 200);

  if (!isValidUsername(usernameRaw)) return bad(res, "Username must be 3–20 chars: letters/numbers/underscore only.");
  if (!password || password.length < 6) return bad(res, "Password must be at least 6 characters.");

  const ranksDb = loadRanks();
  const defaultRank = ranksDb.ranks.find((r) => r.default) || ranksDb.ranks[0];
  const resolvedRankId = Number.isFinite(rankId) ? rankId : (defaultRank && defaultRank.id);
  const rank = ranksDb.ranks.find((r) => r.id === resolvedRankId);
  if (!rank) return bad(res, "Invalid rank.");

  const db = loadUsers();
  const exists = db.users.some((u) => String(u.username).toLowerCase() === username);
  if (exists) return bad(res, "That username is already taken.", 409);

  const user = {
    id: `USR-${id()}`,
    username,
    displayName,
    role: roleFromRank(rank),
    rankId: resolvedRankId,
    passwordHash: bcrypt.hashSync(password, 10),
    createdAt: nowIso(),
    disabled: false,
  };
  db.users.push(user);
  saveUsers(db);
  res.json({ ok: true, id: user.id });
});

app.patch("/api/admin/users/:id", requireAdmin, rateLimit("admin_update_user", 60), (req, res) => {
  const userId = clampStr(req.params.id, 60);
  const db = loadUsers();
  const user = db.users.find((u) => u.id === userId);
  if (!user) return bad(res, "User not found.", 404);

  const displayName = clampStr(req.body.displayName, 40);
  const rankId = req.body.rankId != null ? Number(req.body.rankId) : null;
  const disabled = req.body.disabled;
  const newPassword = clampStr(req.body.password, 200);
  const staffNotes = req.body.staffNotes;
  const disabledReason = clampStr(req.body.disabledReason, 500);
  const disabledUntil = req.body.disabledUntil; // ISO date string or null

  if (displayName) user.displayName = displayName;
  if (Number.isFinite(rankId)) {
    const ranksDb = loadRanks();
    const rank = ranksDb.ranks.find((r) => r.id === rankId);
    if (rank) {
      user.rankId = rankId;
      user.role = roleFromRank(rank);
    }
  }
  if (typeof disabled === "boolean") {
    user.disabled = disabled;
    if (!disabled) {
      user.disabledReason = null;
      user.disabledUntil = null;
    }
  }
  if (typeof staffNotes === "string") user.staffNotes = staffNotes.length ? clampStr(staffNotes, 2000) : null;
  if (req.body.disabledReason !== undefined) user.disabledReason = disabledReason || null;
  if (req.body.disabledUntil !== undefined) {
    if (disabledUntil === null || disabledUntil === "") user.disabledUntil = null;
    else if (typeof disabledUntil === "string") user.disabledUntil = clampStr(disabledUntil, 50);
  }
  if (newPassword) {
    if (newPassword.length < 6) return bad(res, "Password must be at least 6 characters.");
    user.passwordHash = bcrypt.hashSync(newPassword, 10);
  }

  // Prevent disabling the last admin (user with a rank that has accessAdmin)
  const ranksDb = loadRanks();
  const adminRankIds = new Set(ranksDb.ranks.filter((r) => r.permissions && r.permissions.site && r.permissions.site.accessAdmin).map((r) => r.id));
  const admins = db.users.filter((u) => !u.disabled && adminRankIds.has(u.rankId));
  if (admins.length === 0) return bad(res, "You cannot remove the last active admin.", 400);

  saveUsers(db);
  res.json({ ok: true });
});

app.post("/api/admin/users/:id/warn", requireAdmin, rateLimit("admin_warn", 30), (req, res) => {
  const userId = clampStr(req.params.id, 60);
  const reason = clampStr(req.body.reason, 500) || "No reason given.";
  const db = loadUsers();
  const user = db.users.find((u) => u.id === userId);
  if (!user) return bad(res, "User not found.", 404);
  if (!user.warnings) user.warnings = [];
  user.warnings.push({
    at: nowIso(),
    reason,
    byUserId: req.user.id,
    byUsername: req.user.displayName || req.user.username,
  });
  saveUsers(db);
  appendAuditLog({
    userId: req.user.id,
    username: req.user.displayName || req.user.username,
    action: "warn",
    targetType: "user",
    targetId: userId,
    details: { username: user.username, reason },
  });
  res.json({ ok: true, warningsCount: user.warnings.length });
});

app.post("/api/admin/users/:id/warnings/clear", requireAdmin, rateLimit("admin_warn", 20), (req, res) => {
  const userId = clampStr(req.params.id, 60);
  const db = loadUsers();
  const user = db.users.find((u) => u.id === userId);
  if (!user) return bad(res, "User not found.", 404);
  const prev = (user.warnings || []).length;
  user.warnings = [];
  saveUsers(db);
  appendAuditLog({
    userId: req.user.id,
    username: req.user.displayName || req.user.username,
    action: "warnings_clear",
    targetType: "user",
    targetId: userId,
    details: { username: user.username, cleared: prev },
  });
  res.json({ ok: true, cleared: prev });
});

app.delete("/api/admin/users/:id", requireAdmin, rateLimit("admin_delete_user", 30), (req, res) => {
  const userId = clampStr(req.params.id, 60);
  const db = loadUsers();
  const idx = db.users.findIndex((u) => u.id === userId);
  if (idx === -1) return bad(res, "User not found.", 404);

  // Prevent deleting self
  const me = getUserFromSession(req);
  if (me && me.id === userId) return bad(res, "You cannot delete your own account.", 400);

  const deleting = db.users[idx];
  db.users.splice(idx, 1);

  // Prevent deleting last admin (rank has accessAdmin)
  const ranksDb = loadRanks();
  const adminRankIds = new Set(ranksDb.ranks.filter((r) => r.permissions && r.permissions.site && r.permissions.site.accessAdmin).map((r) => r.id));
  const adminsLeft = db.users.filter((u) => !u.disabled && adminRankIds.has(u.rankId));
  if (adminsLeft.length === 0) {
    db.users.splice(idx, 0, deleting);
    return bad(res, "You cannot delete the last active admin.", 400);
  }

  saveUsers(db);
  res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  const sid = req.cookies && req.cookies.pny_session;
  if (sid) {
    const sessions = loadSessions();
    delete sessions.sessions[sid];
    saveSessions(sessions);
  }
  clearCookie(res, "pny_session");
  res.json({ ok: true });
});

app.get("/api/topics", (req, res) => {
  const cat = clampStr(String(req.query.cat || ""), 60);
  const db = loadTopics();
  const catNum = Number(cat);
  const topics = cat
    ? db.topics.filter((t) => (Number.isFinite(catNum) ? t.categoryId === catNum : t.categoryTitle === cat))
    : db.topics;
  const viewer = getUserFromSession(req);
  const filtered = topics
    .filter((t) => canReadForum(viewer, t.categoryId))
    .filter((t) => !t.deletedAt);

  filtered.sort((a, b) => {
    const ap = a.pinnedAt ? 1 : 0;
    const bp = b.pinnedAt ? 1 : 0;
    if (ap !== bp) return bp - ap;
    const at = new Date(a.pinnedAt || a.createdAt).getTime();
    const bt = new Date(b.pinnedAt || b.createdAt).getTime();
    return bt - at;
  });

  res.json({ ok: true, topics: filtered.slice(0, 50) });
});

app.get("/api/topics/:id", (req, res) => {
  const tid = Number(req.params.id);
  if (!Number.isFinite(tid)) return bad(res, "Invalid topic id.");
  const db = loadTopics();
  const topic = db.topics.find((t) => t.id === tid);
  if (!topic) return bad(res, "Topic not found.", 404);
  const viewer = getUserFromSession(req);
  if (!canReadForum(viewer, topic.categoryId)) return bad(res, "Forbidden.", 403);
  if (topic.deletedAt && (!viewer || !canAccessAdmin(viewer))) return bad(res, "Topic not found.", 404);
  const author = topic.author ? { ...topic.author, avatarUrl: getAuthorAvatar(topic.author.id) } : topic.author;
  res.json({ ok: true, topic: { ...topic, author, status: topic.status || "open" } });
});

app.get("/api/topics/:id/replies", (req, res) => {
  const tid = Number(req.params.id);
  if (!Number.isFinite(tid)) return bad(res, "Invalid topic id.");
  const { topic } = getTopicById(tid);
  if (!topic) return bad(res, "Topic not found.", 404);
  const viewer = getUserFromSession(req);
  if (!canReadForum(viewer, topic.categoryId)) return bad(res, "Forbidden.", 403);

  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(50, Math.max(5, parseInt(req.query.limit, 10) || 20));
  const sort = String(req.query.sort || "oldest").toLowerCase() === "newest" ? "newest" : "oldest";

  const db = loadReplies();
  let replies = db.replies.filter((r) => r.topicId === tid && !r.deletedAt);
  const totalCount = replies.length;
  if (sort === "newest") replies = replies.slice().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  else replies = replies.slice().sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  const pinnedReplyId = topic.pinnedReplyId != null ? topic.pinnedReplyId : null;
  if (pinnedReplyId && sort === "oldest") {
    const idx = replies.findIndex((r) => r.id === pinnedReplyId);
    if (idx > 0) {
      const [pinned] = replies.splice(idx, 1);
      replies.unshift(pinned);
    }
  } else if (pinnedReplyId && sort === "newest") {
    const idx = replies.findIndex((r) => r.id === pinnedReplyId);
    if (idx > 0) {
      const [pinned] = replies.splice(idx, 1);
      replies.unshift(pinned);
    }
  }
  const start = (page - 1) * limit;
  const pageReplies = replies.slice(start, start + limit);
  const enriched = pageReplies.map((r) => {
    const author = r.author ? { ...r.author, avatarUrl: getAuthorAvatar(r.author.id) } : r.author;
    return { ...r, author };
  });
  res.json({
    ok: true,
    replies: enriched,
    totalCount,
    page,
    limit,
    sort,
    hasMore: start + pageReplies.length < totalCount,
    pinnedReplyId: pinnedReplyId || null,
  });
});

app.get("/api/topics/:id/watching", (req, res) => {
  const tid = Number(req.params.id);
  if (!Number.isFinite(tid)) return bad(res, "Invalid topic id.");
  const user = getUserFromSession(req);
  if (!user) return res.json({ ok: true, watching: false });
  const db = loadUsers();
  const u = db.users.find((x) => x.id === user.id);
  const list = Array.isArray(u && u.watchedTopicIds) ? u.watchedTopicIds : [];
  res.json({ ok: true, watching: list.indexOf(tid) !== -1 });
});

app.post("/api/topics/:id/watch", requireAuth, rateLimit("watch", 30), (req, res) => {
  const tid = Number(req.params.id);
  if (!Number.isFinite(tid)) return bad(res, "Invalid topic id.");
  const { topic } = getTopicById(tid);
  if (!topic) return bad(res, "Topic not found.", 404);
  if (!canReadForum(req.user, topic.categoryId)) return bad(res, "Forbidden.", 403);

  const db = loadUsers();
  const user = db.users.find((u) => u.id === req.user.id);
  if (!user) return bad(res, "User not found.", 404);
  const list = Array.isArray(user.watchedTopicIds) ? user.watchedTopicIds : [];
  const idx = list.indexOf(tid);
  if (idx === -1) list.push(tid);
  else list.splice(idx, 1);
  user.watchedTopicIds = list;
  saveUsers(db);
  res.json({ ok: true, watching: idx === -1, watchedTopicIds: list });
});

app.get("/api/me/watched", requireAuth, (req, res) => {
  const db = loadUsers();
  const user = db.users.find((u) => u.id === req.user.id);
  const ids = Array.isArray(user && user.watchedTopicIds) ? user.watchedTopicIds : [];
  const topicsDb = loadTopics();
  const viewer = getUserFromSession(req);
  const topics = ids
    .map((id) => topicsDb.topics.find((t) => t.id === id && !t.deletedAt && canReadForum(viewer, t.categoryId)))
    .filter(Boolean)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, 100);
  res.json({ ok: true, topics });
});

app.get("/api/topics/:id/reactions", (req, res) => {
  const tid = Number(req.params.id);
  if (!Number.isFinite(tid)) return bad(res, "Invalid topic id.");
  const { topic } = getTopicById(tid);
  if (!topic) return bad(res, "Topic not found.", 404);
  const viewer = getUserFromSession(req);
  if (!canReadForum(viewer, topic.categoryId)) return bad(res, "Forbidden.", 403);

  const db = loadReactions();
  const reactions = (db.reactions || []).filter((r) => r.topicId === tid);
  res.json({ ok: true, reactions });
});

app.post("/api/reactions", requireAuth, rateLimit("reaction", 60), (req, res) => {
  const postType = clampStr(String(req.body.postType || ""), 10);
  const postId = postType === "topic" ? Number(req.body.postId) : Number(req.body.postId);
  const topicId = Number(req.body.topicId);
  const emoji = clampStr(String(req.body.emoji || ""), 20);

  if (postType !== "topic" && postType !== "reply") return bad(res, "Invalid postType. Use topic or reply.");
  if (!Number.isFinite(postId)) return bad(res, "Invalid postId.");
  if (!Number.isFinite(topicId)) return bad(res, "Invalid topicId.");
  if (!ALLOWED_EMOJIS.has(emoji)) return bad(res, "Invalid emoji. Use: like, heart.");

  const { topic } = getTopicById(topicId);
  if (!topic) return bad(res, "Topic not found.", 404);
  if (!canReadForum(req.user, topic.categoryId)) return bad(res, "Forbidden.", 403);

  if (postType === "reply") {
    const rdb = loadReplies();
    const reply = rdb.replies.find((r) => r.id === postId && r.topicId === topicId && !r.deletedAt);
    if (!reply) return bad(res, "Reply not found.", 404);
  } else if (postId !== topicId) return bad(res, "Topic postId must match topicId.", 400);

  const db = loadReactions();
  const list = db.reactions || [];
  const existing = list.find(
    (r) => r.postType === postType && r.postId === postId && r.topicId === topicId && r.emoji === emoji && r.userId === req.user.id
  );
  if (existing) {
    db.reactions = list.filter((r) => r.id !== existing.id);
    saveReactions(db);
    return res.json({ ok: true, added: false, reactions: db.reactions.filter((r) => r.topicId === topicId) });
  }
  const reaction = {
    id: db.nextId++,
    postType,
    postId,
    topicId,
    emoji,
    userId: req.user.id,
    createdAt: nowIso(),
  };
  db.reactions.push(reaction);
  saveReactions(db);
  res.json({ ok: true, added: true, reactions: db.reactions.filter((r) => r.topicId === topicId) });
});

app.post("/api/topics/:id/replies", requireAuth, rateLimit("reply", 30), (req, res) => {
  const tid = Number(req.params.id);
  if (!Number.isFinite(tid)) return bad(res, "Invalid topic id.");
  const { topic } = getTopicById(tid);
  if (!topic) return bad(res, "Topic not found.", 404);
  if (topic.deletedAt) return bad(res, "Topic not found.", 404);
  if (!canReadForum(req.user, topic.categoryId)) return bad(res, "Forbidden.", 403);
  if (!canPostForum(req.user, topic.categoryId)) return bad(res, "You do not have permission to reply in this forum.", 403);
  if (topic.lockedAt) return bad(res, "This topic is locked.", 423);

  let body = clampStr(req.body.body, 8000);
  if (!body) return bad(res, "Reply body is required.");

  const wfResult = applyWordFilter(body, req.user, topic.categoryId);
  if (wfResult.blocked) return bad(res, "Your post contained content that is not allowed.", 400);
  body = wfResult.body;

  const cats = loadCategories();
  const forum = cats.categories.find((c) => c.type === "forum" && c.id === topic.categoryId);
  const slowMinutes = forum && Number(forum.slowModeMinutes) > 0 ? Number(forum.slowModeMinutes) : 0;
  if (slowMinutes > 0) {
    const lp = loadLastPost();
    const key = `${req.user.id}_${topic.categoryId}`;
    const last = lp.lastPosts && lp.lastPosts[key];
    if (last) {
      const elapsed = (Date.now() - new Date(last).getTime()) / (60 * 1000);
      if (elapsed < slowMinutes) return bad(res, `Slow mode: you can post again in ${Math.ceil(slowMinutes - elapsed)} minute(s).`, 429);
    }
  }

  const parentReplyId = req.body.parentReplyId != null ? Number(req.body.parentReplyId) : null;
  const db = loadReplies();
  const reply = {
    id: db.nextId++,
    topicId: tid,
    body,
    parentReplyId: Number.isFinite(parentReplyId) && parentReplyId > 0 ? parentReplyId : null,
    author: { id: req.user.id, username: req.user.username, displayName: req.user.displayName, role: req.user.role, rankId: req.user.rankId || null },
    createdAt: nowIso(),
    deletedAt: null,
    deletedBy: null,
  };
  db.replies.push(reply);
  saveReplies(db);
  if (slowMinutes > 0) {
    const lp = loadLastPost();
    if (!lp.lastPosts) lp.lastPosts = {};
    lp.lastPosts[`${req.user.id}_${topic.categoryId}`] = nowIso();
    saveLastPost(lp);
  }
  res.json({ ok: true, replyId: reply.id });
});

app.post("/api/topics", requireAuth, rateLimit("topic", 10), (req, res) => {
  const category = clampStr(req.body.category, 60);
  const title = clampStr(req.body.title, 120);
  let body = clampStr(req.body.body, 8000);
  if (!category) return bad(res, "Category is required.");
  if (!title) return bad(res, "Title is required.");
  if (!body) return bad(res, "Body is required.");

  const forumId = Number(category);
  if (!Number.isFinite(forumId)) return bad(res, "Invalid forum.");
  if (!canPostForum(req.user, forumId)) return bad(res, "You do not have permission to post in this forum.", 403);

  const wfResult = applyWordFilter(body, req.user, forumId);
  if (wfResult.blocked) return bad(res, "Your post contained content that is not allowed.", 400);
  body = wfResult.body;

  const cats = loadCategories();
  const forum = cats.categories.find((c) => c.type === "forum" && c.id === forumId);
  const slowMinutes = forum && Number(forum.slowModeMinutes) > 0 ? Number(forum.slowModeMinutes) : 0;
  if (slowMinutes > 0) {
    const lp = loadLastPost();
    const key = `${req.user.id}_${forumId}`;
    const last = lp.lastPosts && lp.lastPosts[key];
    if (last) {
      const elapsed = (Date.now() - new Date(last).getTime()) / (60 * 1000);
      if (elapsed < slowMinutes) return bad(res, `Slow mode: you can post again in ${Math.ceil(slowMinutes - elapsed)} minute(s).`, 429);
    }
  }

  const tagsRaw = req.body.tags;
  const tags = Array.isArray(tagsRaw) ? tagsRaw : (typeof tagsRaw === "string" && tagsRaw.trim() ? tagsRaw.split(",").map((s) => s.trim()) : []);

  const topic = createTopic({
    category: forumId,
    title,
    body,
    author: { id: req.user.id, username: req.user.username, displayName: req.user.displayName, role: req.user.role },
    tags,
  });
  if (slowMinutes > 0) {
    const lp = loadLastPost();
    if (!lp.lastPosts) lp.lastPosts = {};
    lp.lastPosts[`${req.user.id}_${forumId}`] = nowIso();
    saveLastPost(lp);
  }
  const baseUrl = (req.protocol + "://" + (req.get("host") || "localhost")).replace(/\/$/, "");
  const topicUrl = `${baseUrl}/topic.html?id=${topic.id}`;
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (webhookUrl && typeof webhookUrl === "string" && webhookUrl.startsWith("https://discord.com/api/webhooks/")) {
    const authorName = (topic.author && (topic.author.displayName || topic.author.username)) || "Someone";
    const payload = {
      content: null,
      embeds: [{ title: topic.title, description: (topic.body || "").slice(0, 500) + ((topic.body || "").length > 500 ? "…" : ""), url: topicUrl, color: 0x5865f2, footer: { text: `${topic.categoryTitle} · ${authorName}` } }],
    };
    require("https").request(webhookUrl, { method: "POST", headers: { "Content-Type": "application/json" } }, () => {})
      .on("error", (err) => console.error("Discord webhook error:", err.message))
      .end(JSON.stringify(payload));
  }
  res.json({ ok: true, topicId: topic.id });
});

app.patch("/api/topics/:id", requireAuth, rateLimit("topic_edit", 30), (req, res) => {
  const tid = Number(req.params.id);
  if (!Number.isFinite(tid)) return bad(res, "Invalid topic id.");
  const { db, topic } = getTopicById(tid);
  if (!topic) return bad(res, "Topic not found.", 404);
  if (topic.deletedAt) return bad(res, "Topic not found.", 404);
  const isAuthor = topic.author && topic.author.id === req.user.id;
  if (!isAuthor && !canModerateForum(req.user, topic.categoryId)) return bad(res, "Forbidden.", 403);

  let body = clampStr(req.body.body, 8000);
  if (body) {
    const wfResult = applyWordFilter(body, req.user, topic.categoryId);
    if (wfResult.blocked) return bad(res, "Your edit contained content that is not allowed.", 400);
    body = wfResult.body;
    if (!topic.editHistory) topic.editHistory = [];
    topic.editHistory.push({ at: nowIso(), body: topic.body, byUserId: req.user.id });
    topic.body = body;
    topic.updatedAt = nowIso();
    saveTopics(db);
  }
  res.json({ ok: true, topic: { ...topic, updatedAt: topic.updatedAt } });
});

app.patch("/api/topics/:topicId/replies/:replyId", requireAuth, rateLimit("reply_edit", 30), (req, res) => {
  const topicId = Number(req.params.topicId);
  const replyId = Number(req.params.replyId);
  if (!Number.isFinite(topicId) || !Number.isFinite(replyId)) return bad(res, "Invalid id.");
  const { topic } = getTopicById(topicId);
  if (!topic) return bad(res, "Topic not found.", 404);
  const rdb = loadReplies();
  const reply = rdb.replies.find((r) => r.id === replyId && r.topicId === topicId && !r.deletedAt);
  if (!reply) return bad(res, "Reply not found.", 404);
  const isAuthor = reply.author && reply.author.id === req.user.id;
  if (!isAuthor && !canModerateForum(req.user, topic.categoryId)) return bad(res, "Forbidden.", 403);

  let body = clampStr(req.body.body, 8000);
  if (body) {
    const wfResult = applyWordFilter(body, req.user, topic.categoryId);
    if (wfResult.blocked) return bad(res, "Your edit contained content that is not allowed.", 400);
    body = wfResult.body;
    if (!reply.editHistory) reply.editHistory = [];
    reply.editHistory.push({ at: nowIso(), body: reply.body, byUserId: req.user.id });
    reply.body = body;
    reply.updatedAt = nowIso();
    saveReplies(rdb);
  }
  res.json({ ok: true, reply: { ...reply, updatedAt: reply.updatedAt } });
});

app.get("/api/topics/:id/edit-history", (req, res) => {
  const tid = Number(req.params.id);
  if (!Number.isFinite(tid)) return bad(res, "Invalid topic id.");
  const viewer = getUserFromSession(req);
  if (!viewer || (!canAccessAdmin(viewer) && viewer.role !== "staff")) return bad(res, "Forbidden.", 403);
  const { topic } = getTopicById(tid);
  if (!topic) return bad(res, "Topic not found.", 404);
  if (!canReadForum(viewer, topic.categoryId)) return bad(res, "Forbidden.", 403);
  const history = Array.isArray(topic.editHistory) ? topic.editHistory : [];
  res.json({ ok: true, history });
});

app.get("/api/topics/:topicId/replies/:replyId/edit-history", (req, res) => {
  const topicId = Number(req.params.topicId);
  const replyId = Number(req.params.replyId);
  if (!Number.isFinite(topicId) || !Number.isFinite(replyId)) return bad(res, "Invalid id.");
  const viewer = getUserFromSession(req);
  if (!viewer || (!canAccessAdmin(viewer) && viewer.role !== "staff")) return bad(res, "Forbidden.", 403);
  const { topic } = getTopicById(topicId);
  if (!topic) return bad(res, "Topic not found.", 404);
  const rdb = loadReplies();
  const reply = rdb.replies.find((r) => r.id === replyId && r.topicId === topicId);
  if (!reply) return bad(res, "Reply not found.", 404);
  const history = Array.isArray(reply.editHistory) ? reply.editHistory : [];
  res.json({ ok: true, history });
});

app.patch("/api/topics/:id/pin", requireAuth, requireModerateTopic, (req, res) => {
  const { db, topic } = getTopicById(req.topicId);
  if (!topic) return bad(res, "Topic not found.", 404);
  topic.pinnedAt = topic.pinnedAt ? null : nowIso();
  topic.updatedAt = nowIso();
  saveTopics(db);
  appendAuditLog({
    userId: req.user.id,
    username: req.user.displayName || req.user.username,
    action: topic.pinnedAt ? "pin" : "unpin",
    targetType: "topic",
    targetId: topic.id,
    details: { title: topic.title, categoryId: topic.categoryId },
  });
  res.json({ ok: true, pinned: !!topic.pinnedAt });
});

app.patch("/api/topics/:id/pin-reply", requireAuth, requireModerateTopic, (req, res) => {
  const { db, topic } = getTopicById(req.topicId);
  if (!topic) return bad(res, "Topic not found.", 404);
  const replyId = req.body.replyId != null ? Number(req.body.replyId) : null;
  if (replyId !== null && !Number.isFinite(replyId)) return bad(res, "Invalid replyId.");
  const rdb = loadReplies();
  if (replyId !== null) {
    const reply = rdb.replies.find((r) => r.id === replyId && r.topicId === topic.id && !r.deletedAt);
    if (!reply) return bad(res, "Reply not found.", 404);
  }
  topic.pinnedReplyId = replyId;
  topic.updatedAt = nowIso();
  saveTopics(db);
  res.json({ ok: true, pinnedReplyId: topic.pinnedReplyId });
});

app.patch("/api/topics/:id/lock", requireAuth, requireModerateTopic, (req, res) => {
  const { db, topic } = getTopicById(req.topicId);
  if (!topic) return bad(res, "Topic not found.", 404);
  const reason = clampStr(req.body.reason, 300);
  if (topic.lockedAt) {
    topic.lockedAt = null;
    topic.lockedBy = null;
    topic.lockedReason = null;
  } else {
    topic.lockedAt = nowIso();
    topic.lockedBy = req.user.id;
    topic.lockedReason = reason || null;
  }
  topic.updatedAt = nowIso();
  saveTopics(db);
  appendAuditLog({
    userId: req.user.id,
    username: req.user.displayName || req.user.username,
    action: topic.lockedAt ? "lock" : "unlock",
    targetType: "topic",
    targetId: topic.id,
    details: { title: topic.title, reason: topic.lockedReason || undefined },
  });
  res.json({ ok: true, locked: !!topic.lockedAt, lockedReason: topic.lockedReason || null });
});

app.patch("/api/topics/:id/move", requireAuth, requireModerateTopic, (req, res) => {
  const newForumId = Number(req.body.forumId);
  if (!Number.isFinite(newForumId)) return bad(res, "Invalid forumId.");

  const cats = loadCategories();
  const newForum = cats.categories.find((c) => c.type === "forum" && c.id === newForumId);
  if (!newForum) return bad(res, "Forum not found.", 404);

  const { db, topic } = getTopicById(req.topicId);
  if (!topic) return bad(res, "Topic not found.", 404);

  // Require moderation rights in target forum too (or admin)
  if (!canModerateForum(req.user, newForumId)) return bad(res, "Forbidden.", 403);

  topic.categoryId = newForumId;
  topic.categoryTitle = newForum.title;
  topic.updatedAt = nowIso();
  saveTopics(db);
  appendAuditLog({
    userId: req.user.id,
    username: req.user.displayName || req.user.username,
    action: "move",
    targetType: "topic",
    targetId: topic.id,
    details: { title: topic.title, fromCategoryId: topic.categoryId, toCategoryId: newForumId, toTitle: newForum.title },
  });
  res.json({ ok: true });
});

const ACCEPTED_APPEALS_FORUM_ID = 43;
const DENIED_APPEALS_FORUM_ID = 44;
const ACCEPTED_APPLICATIONS_FORUM_ID = 45;
const DENIED_APPLICATIONS_FORUM_ID = 46;
const APPEAL_BOARD_IDS = [40, 41, 42];
const APPLICATION_BOARD_IDS = [30, 31, 32, 33];

app.patch("/api/topics/:id/status", requireAuth, requireModerateTopic, (req, res) => {
  const { db, topic } = getTopicById(req.topicId);
  if (!topic) return bad(res, "Topic not found.", 404);
  const status = clampStr(req.body.status, 20).toLowerCase();
  const allowed = ["open", "hold", "accepted", "denied"];
  if (!status || !allowed.includes(status)) return bad(res, "Invalid status. Use: open, hold, accepted, denied.");
  topic.status = status;
  topic.updatedAt = nowIso();

  // Lock when accepted or denied; unlock when reopened (open)
  if (status === "accepted" || status === "denied") {
    topic.lockedAt = nowIso();
    topic.lockedBy = req.user.id;
    topic.lockedReason = status === "accepted" ? "Accepted" : "Denied";
  } else if (status === "open") {
    topic.lockedAt = null;
    topic.lockedBy = null;
    topic.lockedReason = null;
  }

  const cats = loadCategories();
  const catId = topic.categoryId != null ? Number(topic.categoryId) : null;
  const isAppeal = catId != null && APPEAL_BOARD_IDS.includes(catId);
  const isApplication = catId != null && APPLICATION_BOARD_IDS.includes(catId);
  let moveForumId = null;
  if (isAppeal && status === "accepted") moveForumId = ACCEPTED_APPEALS_FORUM_ID;
  else if (isAppeal && status === "denied") moveForumId = DENIED_APPEALS_FORUM_ID;
  else if (isApplication && status === "accepted") moveForumId = ACCEPTED_APPLICATIONS_FORUM_ID;
  else if (isApplication && status === "denied") moveForumId = DENIED_APPLICATIONS_FORUM_ID;
  if (moveForumId != null) {
    const targetForum = cats.categories.find((c) => c.type === "forum" && c.id === moveForumId);
    if (targetForum && canModerateForum(req.user, moveForumId)) {
      topic.categoryId = moveForumId;
      topic.categoryTitle = targetForum.title;
    }
  }

  saveTopics(db);
  res.json({ ok: true, status: topic.status });
});

app.delete("/api/topics/:id", requireAuth, requireModerateTopic, (req, res) => {
  const tid = req.topicId;
  const topicsDb = loadTopics();
  const topic = topicsDb.topics.find((t) => t && t.id === tid);
  const title = topic ? topic.title : "";

  // Hard delete topic
  const before = topicsDb.topics.length;
  topicsDb.topics = topicsDb.topics.filter((t) => !t || t.id !== tid);
  const after = topicsDb.topics.length;
  saveTopics(topicsDb);

  // Also remove any replies belonging to this topic
  const repliesDb = loadReplies();
  repliesDb.replies = repliesDb.replies.filter((r) => !r || r.topicId !== tid);
  saveReplies(repliesDb);

  if (before === after) return bad(res, "Topic not found.", 404);
  appendAuditLog({
    userId: req.user.id,
    username: req.user.displayName || req.user.username,
    action: "delete",
    targetType: "topic",
    targetId: tid,
    details: { title },
  });
  res.json({ ok: true, deleted: true });
});

app.get("/api/categories", (_req, res) => {
  const db = loadCategories();
  const groups = db.categories.filter((c) => c.type === "group").sort((a, b) => a.id - b.id);
  const forums = db.categories.filter((c) => c.type === "forum");
  const out = groups.map((g) => ({
    ...g,
    forums: forums.filter((f) => f.parentId === g.id).sort((a, b) => a.id - b.id),
  }));
  res.json({ ok: true, groups: out });
});

app.get("/api/categories/flat", (_req, res) => {
  const db = loadCategories();
  const groups = db.categories.filter((c) => c.type === "group").sort((a, b) => a.id - b.id);
  const forums = db.categories.filter((c) => c.type === "forum");
  const viewer = getUserFromSession(_req);
  res.json({
    ok: true,
    groups: groups.map((g) => ({
      id: g.id,
      title: g.title,
      forums: forums
        .filter((f) => f.parentId === g.id)
        .sort((a, b) => a.id - b.id)
        .map((f) => ({
          ...f,
          canRead: canReadForum(viewer, f.id),
          canPost: canPostForum(viewer, f.id),
          canModerate: canModerateForum(viewer, f.id),
        })),
    })),
  });
});

app.get("/api/forum-index", (_req, res) => {
  const cats = loadCategories();
  const topicDb = loadTopics();
  const repliesDb = loadReplies();

  const counts = new Map(); // per-forum total posts (topics + replies)
  const latest = new Map();

  // Pre-compute reply counts per topic
  const replyCounts = new Map();
  for (const r of repliesDb.replies) {
    if (!r || r.deletedAt) continue;
    const key = r.topicId;
    replyCounts.set(key, (replyCounts.get(key) || 0) + 1);
  }

  for (const t of topicDb.topics) {
    if (!t || !t.categoryId || t.deletedAt) continue;
    const topicReplies = replyCounts.get(t.id) || 0;
    counts.set(t.categoryId, (counts.get(t.categoryId) || 0) + 1 + topicReplies);
    if (!latest.has(t.categoryId)) latest.set(t.categoryId, t);
  }

  const groups = cats.categories.filter((c) => c.type === "group").sort((a, b) => a.id - b.id);
  const forums = cats.categories.filter((c) => c.type === "forum");

  const out = groups.map((g) => {
    const siblings = forums.filter((f) => f.parentId === g.id);
    const fs = siblings
      .filter((f) => {
        const t = String(f.title || "").toLowerCase();
        // hide pure status buckets like "Accepted" / "Denied" from main list
        if (t === "accepted" || t === "denied") return false;
        return true;
      })
      .sort((a, b) => a.id - b.id)
      .map((f) => {
        const last = latest.get(f.id) || null;
        // find status children (e.g. Accepted / Denied) under same parent
        const statusChildren = siblings.filter((s) => {
          const t = String(s.title || "").toLowerCase();
          if (s.id === f.id) return false;
          if (s.parentId !== f.parentId) return false;
          return t === "accepted" || t === "denied";
        });

        return {
          id: f.id,
          title: f.title,
          description: f.description || "",
          topicsCount: counts.get(f.id) || 0,
          latestTopic: last
            ? {
                id: last.id,
                title: last.title,
                createdAt: last.createdAt,
                author: last.author ? { ...last.author, avatarUrl: getAuthorAvatar(last.author.id) } : null,
              }
            : null,
          statuses: statusChildren.map((s) => ({
            id: s.id,
            title: s.title,
          })),
        };
      });

    return { id: g.id, title: g.title, description: g.description || "", forums: fs };
  });

  const totalTopics = topicDb.topics.filter((t) => t && !t.deletedAt).length;
  const totalReplies = repliesDb.replies.filter((r) => r && !r.deletedAt).length;

  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.json({
    ok: true,
    groups: out,
    stats: { totalTopics, totalReplies, totalPosts: totalTopics + totalReplies },
  });
});

app.get("/api/admin/topics", requireAdmin, (_req, res) => {
  const topicsDb = loadTopics();
  const repliesDb = loadReplies();

  const replyCounts = new Map();
  for (const r of repliesDb.replies) {
    if (!r || r.deletedAt) continue;
    const key = r.topicId;
    replyCounts.set(key, (replyCounts.get(key) || 0) + 1);
  }

  const items = topicsDb.topics
    .filter((t) => t && t.id)
    .map((t) => ({
      id: t.id,
      title: t.title,
      categoryId: t.categoryId,
      categoryTitle: t.categoryTitle,
      status: t.status || "open",
      lockedAt: t.lockedAt || null,
      lockedReason: t.lockedReason || null,
      pinnedAt: t.pinnedAt || null,
      deletedAt: t.deletedAt || null,
      createdAt: t.createdAt,
      replies: replyCounts.get(t.id) || 0,
      assignedTo: t.assignedTo || null,
      staffNote: t.staffNote || null,
    }))
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  res.json({ ok: true, topics: items });
});

app.post("/api/admin/topics/merge", requireAdmin, rateLimit("admin_bulk", 20), (req, res) => {
  const fromTopicId = Number(req.body.fromTopicId);
  const toTopicId = Number(req.body.toTopicId);
  if (!Number.isFinite(fromTopicId) || !Number.isFinite(toTopicId)) return bad(res, "fromTopicId and toTopicId are required.");
  if (fromTopicId === toTopicId) return bad(res, "Source and target topic must be different.");

  const topicsDb = loadTopics();
  const fromTopic = topicsDb.topics.find((t) => t && t.id === fromTopicId);
  const toTopic = topicsDb.topics.find((t) => t && t.id === toTopicId);
  if (!fromTopic || fromTopic.deletedAt) return bad(res, "Source topic not found.", 404);
  if (!toTopic || toTopic.deletedAt) return bad(res, "Target topic not found.", 404);
  if (!canModerateForum(req.user, fromTopic.categoryId) || !canModerateForum(req.user, toTopic.categoryId)) return bad(res, "Forbidden.", 403);

  const repliesDb = loadReplies();
  const toMove = repliesDb.replies.filter((r) => r && !r.deletedAt && r.topicId === fromTopicId);
  for (const r of toMove) {
    r.topicId = toTopicId;
  }
  fromTopic.deletedAt = nowIso();
  fromTopic.updatedAt = nowIso();
  saveTopics(topicsDb);
  saveReplies(repliesDb);
  appendAuditLog({
    userId: req.user.id,
    username: req.user.displayName || req.user.username,
    action: "merge",
    targetType: "topic",
    targetId: fromTopicId,
    details: { fromTitle: fromTopic.title, toTopicId, toTitle: toTopic.title, repliesMoved: toMove.length },
  });
  res.json({ ok: true, repliesMoved: toMove.length });
});

app.patch("/api/admin/topics/:id", requireAdmin, rateLimit("admin_bulk", 60), (req, res) => {
  const tid = Number(req.params.id);
  if (!Number.isFinite(tid)) return bad(res, "Invalid topic id.");
  const { db, topic } = getTopicById(tid);
  if (!topic) return bad(res, "Topic not found.", 404);
  if (topic.deletedAt) return bad(res, "Topic not found.", 404);

  const assignedTo = req.body.assignedTo !== undefined ? (req.body.assignedTo === null || req.body.assignedTo === "" ? null : clampStr(String(req.body.assignedTo), 60)) : undefined;
  const staffNote = req.body.staffNote !== undefined ? clampStr(req.body.staffNote, 2000) : undefined;

  if (assignedTo !== undefined) topic.assignedTo = assignedTo;
  if (staffNote !== undefined) topic.staffNote = staffNote || null;
  topic.updatedAt = nowIso();
  saveTopics(db);
  res.json({ ok: true, assignedTo: topic.assignedTo || null, staffNote: topic.staffNote || null });
});

app.get("/api/admin/categories", requireAdmin, (_req, res) => {
  const db = loadCategories();
  res.json({ ok: true, ...db });
});

app.post("/api/admin/categories", requireAdmin, rateLimit("admin_cat_create", 40), (req, res) => {
  const type = clampStr(req.body.type, 10);
  const title = clampStr(req.body.title, 80);
  const description = clampStr(req.body.description, 200);
  const parentId = req.body.parentId != null ? Number(req.body.parentId) : null;

  if (type !== "group" && type !== "forum") return bad(res, "Type must be group or forum.");
  if (!title) return bad(res, "Title is required.");

  const db = loadCategories();
  if (type === "forum") {
    if (!Number.isFinite(parentId)) return bad(res, "Forum parentId is required.");
    const parent = db.categories.find((c) => c.id === parentId && c.type === "group");
    if (!parent) return bad(res, "Parent group not found.");
  }

  const node = { id: db.nextId++, type, title, description };
  if (type === "forum") node.parentId = parentId;
  db.categories.push(node);
  saveCategories(db);
  res.json({ ok: true, id: node.id });
});

app.patch("/api/admin/categories/:id", requireAdmin, rateLimit("admin_cat_patch", 80), (req, res) => {
  const idNum = Number(req.params.id);
  if (!Number.isFinite(idNum)) return bad(res, "Invalid category id.");
  const db = loadCategories();
  const node = db.categories.find((c) => c.id === idNum);
  if (!node) return bad(res, "Category not found.", 404);

  const title = clampStr(req.body.title, 80);
  const description = clampStr(req.body.description, 200);
  if (title) node.title = title;
  if (description || description === "") node.description = description;

  if (node.type === "forum" && req.body.parentId != null) {
    const parentId = Number(req.body.parentId);
    if (!Number.isFinite(parentId)) return bad(res, "Invalid parentId.");
    const parent = db.categories.find((c) => c.id === parentId && c.type === "group");
    if (!parent) return bad(res, "Parent group not found.");
    node.parentId = parentId;
  }
  if (node.type === "forum" && req.body.slowModeMinutes != null) {
    const v = Number(req.body.slowModeMinutes);
    node.slowModeMinutes = Number.isFinite(v) && v >= 0 ? v : 0;
  }

  saveCategories(db);
  res.json({ ok: true });
});

app.get("/api/admin/wordfilter", requireAdmin, (req, res) => {
  const wf = loadWordfilter();
  res.json({ ok: true, wordfilter: wf });
});

app.patch("/api/admin/wordfilter", requireAdmin, rateLimit("admin_wordfilter", 20), (req, res) => {
  const wf = loadWordfilter();
  if (Array.isArray(req.body.words)) wf.words = req.body.words.filter((w) => typeof w === "string").map((w) => w.trim()).filter(Boolean);
  if (typeof req.body.replacement === "string") wf.replacement = req.body.replacement.trim().slice(0, 100);
  if (typeof req.body.blockPost === "boolean") wf.blockPost = req.body.blockPost;
  saveWordfilter(wf);
  res.json({ ok: true, wordfilter: wf });
});

app.delete("/api/admin/categories/:id", requireAdmin, rateLimit("admin_cat_delete", 40), (req, res) => {
  const idNum = Number(req.params.id);
  if (!Number.isFinite(idNum)) return bad(res, "Invalid category id.");
  const db = loadCategories();
  const node = db.categories.find((c) => c.id === idNum);
  if (!node) return bad(res, "Category not found.", 404);

  if (node.type === "group") {
    const hasChildren = db.categories.some((c) => c.type === "forum" && c.parentId === node.id);
    if (hasChildren) return bad(res, "Delete subforums first.", 400);
  }

  db.categories = db.categories.filter((c) => c.id !== idNum);
  saveCategories(db);
  res.json({ ok: true });
});

app.post("/api/staff-application", requireAuth, rateLimit("staff", 6), (req, res) => {
  const steam = clampStr(req.body.steam, 200);
  const discord = clampStr(req.body.discord, 80);
  const age = clampStr(String(req.body.age ?? ""), 3);
  const tz = clampStr(req.body.tz, 30);
  const experience = clampStr(req.body.experience, 2000);
  const why = clampStr(req.body.why, 2000);
  const availability = clampStr(req.body.availability, 1000);
  const history = clampStr(req.body.history, 2000);

  if (!steam) return bad(res, "Steam profile URL is required.");
  if (!age || Number.isNaN(Number(age))) return bad(res, "Age is required.");
  if (!tz) return bad(res, "Timezone is required.");
  if (!experience) return bad(res, "Experience is required.");
  if (!why) return bad(res, "Why is required.");
  if (!availability) return bad(res, "Availability is required.");

  const record = {
    id: `STAFF-${id()}`,
    createdAt: nowIso(),
    steam,
    discord,
    age: Number(age),
    tz,
    experience,
    why,
    availability,
    history,
    meta: {
      ip: req.ip,
      ua: clampStr(req.headers["user-agent"] || "", 200),
    },
  };

  appendJsonl(staffFile, record);
  const topic = createTopic({
    category: 30,
    title: `Staff Application — ${discord || steam}`,
    body:
      `**Steam:** ${steam}\n` +
      `**Discord:** ${discord || "(not provided)"}\n` +
      `**Age:** ${Number(age)}\n` +
      `**Timezone:** ${tz}\n\n` +
      `## RP experience\n${experience}\n\n` +
      `## Why staff?\n${why}\n\n` +
      `## Availability\n${availability}\n\n` +
      `## Moderation history\n${history || "(none)"}\n`,
    author: { id: req.user.id, username: req.user.username, displayName: req.user.displayName, role: req.user.role },
  });
  res.json({ ok: true, id: record.id, topicId: topic.id });
});

app.post("/api/appeal", requireAuth, rateLimit("appeal", 6), (req, res) => {
  const steam = clampStr(req.body.steam, 200);
  const type = clampStr(req.body.type, 20);
  const date = clampStr(req.body.date, 20);
  const staff = clampStr(req.body.staff, 80);
  const what = clampStr(req.body.what, 3000);
  const evidence = clampStr(req.body.evidence, 3000);
  const change = clampStr(req.body.change, 3000);

  if (!steam) return bad(res, "Steam profile URL is required.");
  if (!type) return bad(res, "Appeal type is required.");
  if (!date) return bad(res, "Date is required.");
  if (!what) return bad(res, "What happened is required.");
  if (!evidence) return bad(res, "Evidence is required.");
  if (!change) return bad(res, "What will you do differently is required.");

  const record = {
    id: `APPEAL-${id()}`,
    createdAt: nowIso(),
    steam,
    type,
    date,
    staff,
    what,
    evidence,
    change,
    meta: {
      ip: req.ip,
      ua: clampStr(req.headers["user-agent"] || "", 200),
    },
  };

  appendJsonl(appealFile, record);
  const appealForumId = Number(req.body.forumId) || 40;
  const topic = createTopic({
    category: appealForumId,
    title: `${type.toUpperCase()} Appeal — ${discordSafe(req.body.discord)}${discordSafe(req.body.discord) ? "" : steam}`,
    body:
      `**Steam:** ${steam}\n` +
      `**Type:** ${type}\n` +
      `**Date:** ${date}\n` +
      `**Staff (if known):** ${staff || "(unknown)"}\n\n` +
      `## What happened?\n${what}\n\n` +
      `## Evidence\n${evidence}\n\n` +
      `## What will you do differently?\n${change}\n`,
    author: { id: req.user.id, username: req.user.username, displayName: req.user.displayName, role: req.user.role },
  });
  res.json({ ok: true, id: record.id, topicId: topic.id });
});

function discordSafe(v) {
  const s = clampStr(v, 80);
  return s ? `${s} — ` : "";
}

function getTopicById(tid) {
  const db = loadTopics();
  const id = typeof tid === "number" && Number.isFinite(tid) ? tid : Number(tid);
  const topic = db.topics.find((t) => t && (t.id === id || t.id === tid));
  return { db, topic };
}

function requireModerateTopic(req, res, next) {
  const tid = Number(req.params.id);
  if (!Number.isFinite(tid)) return bad(res, "Invalid topic id.");
  const { topic } = getTopicById(tid);
  if (!topic) return bad(res, "Topic not found.", 404);
  if (!canModerateForum(req.user, topic.categoryId)) return bad(res, "Forbidden.", 403);
  req.topicId = tid;
  next();
}

function handleReport(req, res) {
  const postType = clampStr(String(req.body.postType || ""), 10);
  const postId = Number(req.body.postId);
  const topicId = Number(req.body.topicId);
  const reason = clampStr(req.body.reason, 2000);

  if (postType !== "topic" && postType !== "reply") return bad(res, "Invalid postType. Use topic or reply.");
  if (!Number.isFinite(postId)) return bad(res, "Invalid postId.");
  if (!Number.isFinite(topicId)) return bad(res, "Invalid topicId.");
  if (!reason) return bad(res, "Reason is required.");

  const { topic } = getTopicById(topicId);
  if (!topic) return bad(res, "Topic not found.", 404);
  if (!canReadForum(req.user, topic.categoryId)) return bad(res, "Forbidden.", 403);

  if (postType === "reply") {
    const rdb = loadReplies();
    const reply = rdb.replies.find((r) => r.id === postId && r.topicId === topicId && !r.deletedAt);
    if (!reply) return bad(res, "Reply not found.", 404);
  } else if (postId !== topicId) return bad(res, "Topic postId must match topicId.", 400);

  const record = {
    id: `REP-${id()}`,
    postType,
    postId,
    topicId,
    reason,
    reportedBy: req.user.id,
    reportedByName: req.user.displayName || req.user.username,
    createdAt: nowIso(),
  };
  appendJsonl(reportsFile, record);
  res.json({ ok: true, id: record.id });
}

app.post("/api/report", requireAuth, rateLimit("report", 20), handleReport);
// Support /report in case client or proxy sends there
app.post("/report", requireAuth, rateLimit("report", 20), handleReport);

// In-game tickets: create (API key or auth), list and resolve (staff only)
function canCreateTicket(req) {
  if (process.env.TICKETS_API_KEY && req.get("x-api-key") === process.env.TICKETS_API_KEY) return true;
  return !!getUserFromSession(req);
}

app.post("/api/tickets", rateLimit("tickets", 120), (req, res) => {
  if (!canCreateTicket(req)) return bad(res, "Unauthorized. Use x-api-key header (in-game) or sign in.", 401);
  const serverId = clampStr(String(req.body.serverId || req.body.server || ""), 20);
  const playerName = clampStr(String(req.body.playerName || req.body.player || ""), 120);
  const steamId = clampStr(String(req.body.steamId || ""), 40);
  const message = clampStr(String(req.body.message || req.body.text || ""), 2000);
  const category = clampStr(String(req.body.category || "general"), 40);
  if (!playerName && !steamId) return bad(res, "playerName or steamId required.", 400);
  if (!message) return bad(res, "message required.", 400);
  const record = {
    id: "TKT-" + id(),
    serverId: serverId || "1",
    serverName: serverId === "1" ? (process.env.SAM_SERVER_NAME || "Project New York") : "Server " + serverId,
    playerName: playerName || "—",
    steamId: steamId || null,
    message,
    category,
    createdAt: nowIso(),
  };
  appendJsonl(ticketsFile, record);
  res.json({ ok: true, id: record.id });
});

app.get("/api/tickets", requireStaff, (req, res) => {
  const serverId = clampStr(String(req.query.server || req.query.serverId || ""), 20);
  let tickets = readJsonlLines(ticketsFile, 300).reverse();
  if (serverId) tickets = tickets.filter((t) => (t.serverId || "") === serverId);
  const reso = loadTicketResolutions();
  const merged = tickets.map((t) => {
    const r = (reso.resolutions || {})[t.id] || {};
    return {
      ...t,
      status: r.status || "open",
      resolvedAt: r.resolvedAt || null,
      resolvedBy: r.resolvedBy || null,
      resolvedByName: r.resolvedByName || null,
      resolutionNote: r.note || null,
    };
  });
  res.json({ ok: true, tickets: merged });
});

app.patch("/api/tickets/:id/resolve", requireStaff, rateLimit("admin_resolve", 60), (req, res) => {
  const ticketId = clampStr(req.params.id, 80);
  const status = clampStr(String(req.body.status || ""), 20).toLowerCase();
  const note = clampStr(req.body.note, 500);
  const allowed = ["open", "claimed", "resolved", "dismissed"];
  if (!allowed.includes(status)) return bad(res, "status must be: open, claimed, resolved, dismissed.");
  const tickets = readJsonlLines(ticketsFile, 500);
  const ticket = tickets.find((t) => t.id === ticketId);
  if (!ticket) return bad(res, "Ticket not found.", 404);
  const reso = loadTicketResolutions();
  if (!reso.resolutions) reso.resolutions = {};
  reso.resolutions[ticketId] = {
    status,
    resolvedAt: (status === "resolved" || status === "dismissed") ? nowIso() : null,
    resolvedBy: req.user.id,
    resolvedByName: req.user.displayName || req.user.username,
    note: note || null,
  };
  saveTicketResolutions(reso);
  res.json({ ok: true, resolution: reso.resolutions[ticketId] });
});

app.get("/api/admin/reports", requireAdmin, (req, res) => {
  const reports = readJsonlLines(reportsFile, 200).reverse();
  const reso = loadReportResolutions();
  const merged = reports.map((r) => {
    const res = (reso.resolutions || {})[r.id] || {};
    return {
      ...r,
      resolutionStatus: res.status || "pending",
      resolvedAt: res.resolvedAt || null,
      resolvedBy: res.resolvedBy || null,
      resolvedByName: res.resolvedByName || null,
      resolutionNote: res.note || null,
    };
  });
  res.json({ ok: true, reports: merged });
});

app.patch("/api/admin/reports/:id/resolve", requireAdmin, rateLimit("admin_resolve", 60), (req, res) => {
  const reportId = clampStr(req.params.id, 80);
  const status = clampStr(String(req.body.status || ""), 20).toLowerCase();
  const note = clampStr(req.body.note, 500);
  const allowed = ["pending", "resolved", "dismissed"];
  if (!allowed.includes(status)) return bad(res, "status must be: pending, resolved, dismissed.");
  const reports = readJsonlLines(reportsFile, 500);
  const report = reports.find((r) => r.id === reportId);
  if (!report) return bad(res, "Report not found.", 404);
  const reso = loadReportResolutions();
  if (!reso.resolutions) reso.resolutions = {};
  reso.resolutions[reportId] = {
    status,
    resolvedAt: (status === "resolved" || status === "dismissed") ? nowIso() : null,
    resolvedBy: req.user.id,
    resolvedByName: req.user.displayName || req.user.username,
    note: note || null,
  };
  saveReportResolutions(reso);
  res.json({ ok: true, resolution: reso.resolutions[reportId] });
});

app.get("/api/admin/mod-dashboard", requireAdmin, (req, res) => {
  const reports = readJsonlLines(reportsFile, 300);
  const reso = loadReportResolutions();
  const openReportsCount = reports.filter((r) => ((reso.resolutions || {})[r.id] || {}).status !== "resolved" && ((reso.resolutions || {})[r.id] || {}).status !== "dismissed").length;
  const topicsDb = loadTopics();
  const cats = loadCategories();
  const appealsGroup = cats.categories.find((c) => c.type === "group" && (c.title || "").toLowerCase().includes("appeal"));
  const appealForumIds = appealsGroup ? cats.categories.filter((c) => c.type === "forum" && c.parentId === appealsGroup.id).map((c) => c.id) : [40, 41, 42];
  const openAppealsCount = topicsDb.topics.filter((t) => t && !t.deletedAt && appealForumIds.includes(t.categoryId) && ["open", "hold"].includes((t.status || "open").toLowerCase())).length;
  const usersDb = loadUsers();
  const usersWithWarningsCount = usersDb.users.filter((u) => !u.disabled && Array.isArray(u.warnings) && u.warnings.length >= 3).length;
  res.json({
    ok: true,
    openReportsCount,
    openAppealsCount,
    usersWithWarningsCount,
  });
});

app.get("/api/admin/stats", requireAdmin, (req, res) => {
  const topicsDb = loadTopics();
  const repliesDb = loadReplies();
  const usersDb = loadUsers();
  const sessions = loadSessions();
  const now = Date.now();
  const oneDay = 24 * 60 * 60 * 1000;
  const topics = topicsDb.topics.filter((t) => t && !t.deletedAt);
  const replies = repliesDb.replies.filter((r) => r && !r.deletedAt);
  const users = usersDb.users.filter((u) => !u.disabled);

  const topicsByDay = [0, 0, 0, 0, 0, 0, 0];
  const repliesByDay = [0, 0, 0, 0, 0, 0, 0];
  for (let i = 0; i < 7; i++) {
    const dayStart = now - (6 - i) * oneDay;
    const dayEnd = dayStart + oneDay;
    topicsByDay[i] = topics.filter((t) => {
      const ts = new Date(t.createdAt).getTime();
      return ts >= dayStart && ts < dayEnd;
    }).length;
    repliesByDay[i] = replies.filter((r) => {
      const ts = new Date(r.createdAt).getTime();
      return ts >= dayStart && ts < dayEnd;
    }).length;
  }

  const byCategory = {};
  for (const t of topics) {
    const cid = t.categoryId != null ? t.categoryId : 0;
    byCategory[cid] = (byCategory[cid] || 0) + 1;
    const rc = replies.filter((r) => r.topicId === t.id).length;
    byCategory[cid] = (byCategory[cid] || 0) + rc;
  }
  const categoryList = Object.entries(byCategory)
    .map(([id, count]) => ({ categoryId: Number(id), count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  const onlineCount = Object.keys(sessions.sessions || {}).length;

  res.json({
    ok: true,
    stats: {
      topicsCount: topics.length,
      repliesCount: replies.length,
      usersCount: users.length,
      onlineCount,
      topicsLast7Days: topicsByDay,
      repliesLast7Days: repliesByDay,
      byCategory: categoryList,
    },
  });
});

app.get("/api/admin/audit", requireAdmin, (req, res) => {
  const lines = Math.min(Math.max(1, parseInt(req.query.limit, 10) || 100), 500);
  let entries = readJsonlLines(auditFile, lines).reverse();
  const action = clampStr(String(req.query.action || ""), 30);
  const username = clampStr(String(req.query.username || ""), 80).toLowerCase();
  const from = req.query.from ? new Date(req.query.from).getTime() : null;
  const to = req.query.to ? new Date(req.query.to).getTime() : null;
  if (action) entries = entries.filter((e) => (e.action || "").toLowerCase() === action.toLowerCase());
  if (username) entries = entries.filter((e) => (e.username || "").toLowerCase().includes(username));
  if (Number.isFinite(from)) entries = entries.filter((e) => new Date(e.at).getTime() >= from);
  if (Number.isFinite(to)) entries = entries.filter((e) => new Date(e.at).getTime() <= to);
  res.json({ ok: true, entries });
});

app.post("/api/admin/topics/bulk", requireAdmin, rateLimit("admin_bulk", 30), (req, res) => {
  const topicIds = Array.isArray(req.body.topicIds) ? req.body.topicIds.map((id) => Number(id)).filter(Number.isFinite) : [];
  const action = clampStr(String(req.body.action || ""), 20).toLowerCase();
  const forumId = req.body.forumId != null ? Number(req.body.forumId) : null;

  if (topicIds.length === 0) return bad(res, "topicIds array is required.");
  const allowed = ["lock", "unlock", "pin", "unpin", "delete", "move"];
  if (!allowed.includes(action)) return bad(res, "action must be one of: lock, unlock, pin, unpin, delete, move.");
  if (action === "move" && !Number.isFinite(forumId)) return bad(res, "forumId is required for move.");

  const topicsDb = loadTopics();
  const cats = loadCategories();
  const results = { done: 0, failed: 0, errors: [] };
  const deletedTopicIds = new Set();

  for (const tid of topicIds) {
    const topic = topicsDb.topics.find((t) => t && t.id === tid);
    if (!topic) {
      results.failed += 1;
      results.errors.push({ topicId: tid, error: "not found" });
      continue;
    }
    if (topic.deletedAt) {
      results.failed += 1;
      results.errors.push({ topicId: tid, error: "already deleted" });
      continue;
    }
    if (!canModerateForum(req.user, topic.categoryId)) {
      results.failed += 1;
      results.errors.push({ topicId: tid, error: "forbidden" });
      continue;
    }
    try {
      if (action === "lock") {
        topic.lockedAt = nowIso();
        topic.lockedBy = req.user.id;
        topic.updatedAt = nowIso();
        results.done += 1;
        appendAuditLog({ userId: req.user.id, username: req.user.displayName || req.user.username, action: "lock", targetType: "topic", targetId: tid, details: { title: topic.title } });
      } else if (action === "unlock") {
        topic.lockedAt = null;
        topic.lockedBy = null;
        topic.updatedAt = nowIso();
        results.done += 1;
        appendAuditLog({ userId: req.user.id, username: req.user.displayName || req.user.username, action: "unlock", targetType: "topic", targetId: tid, details: { title: topic.title } });
      } else if (action === "pin") {
        topic.pinnedAt = nowIso();
        topic.updatedAt = nowIso();
        results.done += 1;
        appendAuditLog({ userId: req.user.id, username: req.user.displayName || req.user.username, action: "pin", targetType: "topic", targetId: tid, details: { title: topic.title } });
      } else if (action === "unpin") {
        topic.pinnedAt = null;
        topic.updatedAt = nowIso();
        results.done += 1;
        appendAuditLog({ userId: req.user.id, username: req.user.displayName || req.user.username, action: "unpin", targetType: "topic", targetId: tid, details: { title: topic.title } });
      } else if (action === "move") {
        const newForum = cats.categories.find((c) => c.type === "forum" && c.id === forumId);
        if (!newForum || !canModerateForum(req.user, forumId)) {
          results.failed += 1;
          results.errors.push({ topicId: tid, error: "invalid forum or forbidden" });
          continue;
        }
        topic.categoryId = forumId;
        topic.categoryTitle = newForum.title;
        topic.updatedAt = nowIso();
        results.done += 1;
        appendAuditLog({ userId: req.user.id, username: req.user.displayName || req.user.username, action: "move", targetType: "topic", targetId: tid, details: { title: topic.title, toCategoryId: forumId, toTitle: newForum.title } });
      } else if (action === "delete") {
        topicsDb.topics = topicsDb.topics.filter((t) => !t || t.id !== tid);
        deletedTopicIds.add(tid);
        results.done += 1;
        appendAuditLog({ userId: req.user.id, username: req.user.displayName || req.user.username, action: "delete", targetType: "topic", targetId: tid, details: { title: topic.title } });
      }
    } catch (err) {
      results.failed += 1;
      results.errors.push({ topicId: tid, error: String(err.message || "error") });
    }
  }

  saveTopics(topicsDb);
  if (action === "delete" && deletedTopicIds.size > 0) {
    const repliesDb = loadReplies();
    repliesDb.replies = repliesDb.replies.filter((r) => !r || !deletedTopicIds.has(r.topicId));
    saveReplies(repliesDb);
  }
  res.json({ ok: true, results });
});

// Unmatched API routes → JSON 404 (so client doesn't get HTML "Cannot POST ...")
app.use("/api", (req, res) => {
  res.status(404).json({ ok: false, error: `Not found: ${req.method} ${req.path}` });
});

// Protect admin page: only admins can load it (prevents info leakage and forces login)
app.get("/admin.html", (req, res, next) => {
  const user = getUserFromSession(req);
  if (!user || !canAccessAdmin(user)) {
    const redirect = encodeURIComponent("/admin.html");
    return res.redirect(302, `/signin.html?redirect=${redirect}`);
  }
  res.sendFile(path.join(__dirname, "admin.html"));
});

// Serve the static site (HTML/CSS/JS)
app.use(
  express.static(__dirname, {
    index: ["index.html"],
    extensions: ["html"],
  })
);

app.listen(PORT, () => {
  console.log(`Project New York running at http://localhost:${PORT}`);
});

