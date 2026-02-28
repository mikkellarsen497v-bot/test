# Step-by-step: Show SAM bans on your website

This guide gets your Project New York site showing the same bans as your Garry's Mod server (SAM on SparkedHost), using one MySQL database.

---

## What you need

- A SparkedHost game server with SAM installed
- A MySQL database (from SparkedHost or the same server)
- This website (Node app) running somewhere that can reach that MySQL (same host, or SparkedHost allows remote MySQL)

---

## Step 1: Get or create a MySQL database

1. Log in to **SparkedHost**: https://control.sparkedhost.com/
2. Open your **game server** (Garry's Mod).
3. Look for **Databases**, **MySQL**, or **Database** in the left menu or tabs.
4. **If you already have a database:** note down:
   - **Host** (e.g. `localhost`, an IP, or something like `srv123.sparkedhost.com`)
   - **Database name**
   - **Username**
   - **Password**
5. **If you need to create one:** click **New Database** (or similar), choose MySQL, set a name and password, and note the **host** they give you. Some panels show the host only after creation.

---

## Step 2: Point SAM (GMod) at MySQL

1. On your PC (or via FTP / File Manager), open your SAM addon folder. The config file is usually at:
   - `garrysmod/lua/sam_sql_config.lua`
   Or in your addon: `lua/sam_sql_config.lua`
2. Open `sam_sql_config.lua` in a text editor.
3. Set it to use MySQL and your SparkedHost details:

```lua
return {
    MySQL = true,

    Host = "YOUR_MYSQL_HOST",      -- from Step 1 (e.g. localhost or the host SparkedHost gave you)
    Username = "YOUR_MYSQL_USER",
    Password = "YOUR_MYSQL_PASSWORD",
    Database = "YOUR_DATABASE_NAME",
}
```

4. Replace the placeholders with the **exact** host, username, password, and database name from Step 1.
5. Save the file and upload it to the server if you edited locally.
6. Restart your Garry's Mod server (or the server will load the new config on next map load). SAM will create the `sam_bans` and `sam_players` tables in MySQL the first time it runs with MySQL enabled.

---

## Step 3: Allow the website to reach MySQL (if needed)

- **If the website runs on the same machine as the game server:** use `Host = "localhost"` in both SAM and the website; no extra step.
- **If the website runs elsewhere** (e.g. your PC, Railway, another host):
  1. In SparkedHost’s panel, find the database **remote access** or **allowed IPs** setting.
  2. Add the **IP address** of the machine where the website runs (e.g. your home IP or your cloud server’s IP).
  3. Use the **public MySQL host** SparkedHost gives for remote connections (often your node hostname or a dedicated DB host), not `localhost`.

---

## Step 4: Configure the website (.env)

1. Open your website project folder and find the **`.env`** file (same folder as `server.js`).
2. Set the **same** MySQL details as in Step 2:

```env
SAM_MYSQL_HOST=sparkedhost.com
SAM_MYSQL_PORT=3306
SAM_MYSQL_USER=your_actual_username
SAM_MYSQL_PASSWORD=your_actual_password
SAM_MYSQL_DATABASE=your_actual_database_name
SAM_SERVER_NAME=WW2 Imperial Germany RP
```

3. **Important:** Use the **same host** you used in `sam_sql_config.lua`. If SparkedHost gave you an IP or a hostname like `srv123.sparkedhost.com`, use that instead of `sparkedhost.com`.
4. Save `.env`. Do **not** commit it to git (it should be in `.gitignore`).

---

## Step 5: Install dependencies and start the site

1. In the website folder, open a terminal and run:

```bash
npm install
npm start
```

2. If you use a different command to run the site (e.g. `node server.js`), use that instead of `npm start`.

---

## Step 6: Check that it works

1. Open your site in a browser and go to the **Bans** page (e.g. `http://localhost:3000/bans.html` or your live URL).
2. You should see the same bans as in SAM (and in the in-game SAM menu).
3. **If the list is empty:** make sure you have at least one ban in SAM and that both SAM and the website use the same MySQL database and credentials.
4. **If you see “Failed to load bans” or no data:**  
   - Check that `SAM_MYSQL_*` in `.env` match `sam_sql_config.lua`.  
   - If the website is on a different server, check that SparkedHost allows your website’s IP to connect to MySQL and that you’re using the remote host they provided.

---

## Optional: Use the sync script instead of MySQL

If you **don’t** want the website to connect to MySQL (e.g. no remote access), you can export SAM bans into a file and let the site read that:

1. **If SAM uses MySQL:** set the same `SAM_MYSQL_*` in `.env`, then run:

```bash
npm run sync-sam-bans
```

This writes bans from MySQL to `data/bans.json`. The site will then use `data/bans.json` if you **remove or comment out** the `SAM_MYSQL_*` lines in `.env` (so the server doesn’t try to connect to MySQL).

2. **If SAM uses SQLite:** copy the SAM SQLite file from your server (often in the garrysmod folder) to your PC, then run:

```bash
npm install better-sqlite3
node scripts/sync-sam-bans.js "C:\path\to\sam.sqlite"
```

Replace the path with the real location of the `.sqlite` file. Then comment out the `SAM_MYSQL_*` lines in `.env` so the site uses `data/bans.json`.

---

## Quick checklist

- [ ] MySQL database created / credentials from SparkedHost written down  
- [ ] `sam_sql_config.lua` has `MySQL = true` and correct Host, Username, Password, Database  
- [ ] Game server restarted so SAM uses MySQL  
- [ ] `.env` has same `SAM_MYSQL_HOST`, `SAM_MYSQL_USER`, `SAM_MYSQL_PASSWORD`, `SAM_MYSQL_DATABASE`  
- [ ] If website is on another machine, SparkedHost allows that IP for MySQL and you use the remote host  
- [ ] `npm install` and `npm start` (or your start command) run without errors  
- [ ] Bans page loads and shows bans from SAM  

If something doesn’t work, double-check host/user/password/database in both SAM and `.env`, and that the website process can reach the MySQL port (usually 3306).
