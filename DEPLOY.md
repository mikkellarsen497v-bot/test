# Deploying Project New York

This app is a Node.js + Express forum with file-based data in the `data/` folder. Use one of the options below to host it on the web.

---

## Before you deploy

1. **Git**: Put the project in a Git repo (e.g. GitHub). All hosts can deploy from a repo.
2. **Secrets**: Do not commit `.env`. Use each platform’s environment variables for any secrets.
3. **Data**: The app writes users, topics, and reports to `data/`. For production, use a **persistent volume** (or disk) so data survives restarts and redeploys.

---

## Option 1: Railway

1. Sign up at [railway.app](https://railway.app) and create a **New Project**.
2. **Add service** → **GitHub repo** → select your repo. Root directory should be the folder that contains `package.json` and `server.js`.
3. Railway will detect the Dockerfile and build. Set **Start Command** to `node server.js` if needed (already in Dockerfile CMD).
4. **Add volume**: In the service, open **Variables** or **Settings** → **Volumes** → **Add Volume**. Set mount path to **`/app/data`**. This keeps forum data across deploys.
5. **Settings** → **Networking** → **Generate Domain**. You’ll get a URL like `https://your-app.up.railway.app`.
6. Optional: set `NODE_ENV=production` in Variables.

---

## Option 2: Render

1. Sign up at [render.com](https://render.com). **New** → **Web Service**.
2. Connect your GitHub repo. Select the repo and branch.
3. **Environment**: Docker. Render will use the repo’s `Dockerfile`.
4. **Instance type**: Free or paid. Free tier has **no persistent disk** — `data/` is reset on each deploy. For a real site, use a paid plan and add a disk (see below).
5. Click **Create Web Service**. Render assigns a URL like `https://project-new-york.onrender.com`.
6. **Optional (paid) persistent data**: In the service → **Disks** → **Add Disk** (e.g. name `pny-data`, mount path `/data`, size 1 GB). In **Environment** add `DATA_DIR=/data`.

---

## Option 3: Fly.io

1. Install the CLI: [fly.io/docs/hands-on/install-flyctl](https://fly.io/docs/hands-on/install-flyctl).
2. Log in: `fly auth login`.
3. From the project root (where `fly.toml` is), create a volume for data:
   ```bash
   fly volumes create pny_data --region ord --size 1
   ```
   Replace `ord` with your preferred region (e.g. `lax`, `ams`).
4. Launch the app (first time only):
   ```bash
   fly launch
   ```
   Use the existing `fly.toml`; say no to copying config if asked. Set app name if you want.
5. Deploy:
   ```bash
   fly deploy
   ```
6. Open the site: `fly open`. Your app will be at `https://<app-name>.fly.dev`. Data is stored on the `pny_data` volume.

---

## Option 4: VPS (Ubuntu/Debian with PM2 + Nginx)

Use a server (e.g. DigitalOcean, Linode, Vultr) with Ubuntu 22.04.

### 1. Server setup

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y nodejs npm nginx git
# Or use Node 20 via NodeSource:
# curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt install -y nodejs
```

### 2. Install PM2 and run the app

```bash
sudo npm install -g pm2
cd /var/www   # or your chosen directory
sudo git clone https://github.com/YOUR_USER/YOUR_REPO.git pny
cd pny
npm ci --omit=dev
pm2 start ecosystem.config.cjs --env production
pm2 save
pm2 startup   # run the command it prints so the app starts on reboot
```

### 3. Nginx reverse proxy

```bash
sudo cp nginx.conf.example /etc/nginx/sites-available/pny
sudo sed -i 's/yourdomain.com/YOUR_ACTUAL_DOMAIN/g' /etc/nginx/sites-available/pny
sudo ln -s /etc/nginx/sites-available/pny /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### 4. HTTPS with Let’s Encrypt

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

### 5. Deploy updates

From the app directory:

```bash
git pull
./scripts/deploy-vps.sh
```

Or manually: `npm ci --omit=dev` then `pm2 reload ecosystem.config.cjs --env production` and `pm2 save`.

---

## Environment variables

| Variable     | Description                    | Default   |
|-------------|--------------------------------|-----------|
| `PORT`      | Server port                    | `3000`    |
| `NODE_ENV`  | `production` recommended       | —         |
| `DATA_DIR`  | Persistent data path (optional)| `./data`  |

Set these in each platform’s dashboard (or in `.env` locally; see `.env.example`). Do not commit `.env`.

---

## After deploy

- **Admin**: Default admin user is created on first run. Credentials are written to `ADMIN_LOGIN.txt` in the app root (or check `data/users.json`). Change the password after first login.
- **Backups**: For production, back up the `data/` folder (or your `DATA_DIR`) regularly.
- **Logs**: Use the host’s log viewer, or on VPS: `pm2 logs pny`.
