# Deploying Project New York with InfinityFree + Render

InfinityFree only supports PHP/static files, not Node.js. So you run the **API (Node app)** on **Render** (free) and put the **website (HTML/CSS/JS)** on **InfinityFree**. Visitors use your InfinityFree URL; the pages call the API on Render.

## 1. Deploy the API on Render

1. Put your project in a **GitHub** repo (include `server.js`, `package.json`, all HTML/CSS/JS, `data/` if you use it; **do not** commit `node_modules` or `.env`).
2. Go to [render.com](https://render.com) → **New** → **Web Service**.
3. Connect the repo. Set:
   - **Build command:** `npm install`
   - **Start command:** `node server.js`
4. In **Environment** add:
   - `STEAM_API_KEY` = your Steam key
   - `BASE_URL` = your **Render** API URL (e.g. `https://your-app-name.onrender.com`) — Steam needs this as the callback host
   - `FRONTEND_URL` = your **InfinityFree** site URL (e.g. `https://yoursite.epizy.com`) — after Steam login users are sent here
   - `ALLOWED_ORIGIN` = same as `FRONTEND_URL` (e.g. `https://yoursite.epizy.com`) — so the browser can call the API from your InfinityFree pages
5. Deploy. Copy the Render URL (e.g. `https://project-new-york.onrender.com`).

## 2. Upload the site to InfinityFree

1. In **File Manager** on InfinityFree, open **htdocs**.
2. Upload everything **except**:
   - `node_modules/`
   - `server.js` (optional: you can leave it; it won’t run)
   - `.env`
   - `package.json` / `package-lock.json` (optional)
3. You **must** upload:
   - All **`.html`** files
   - **`styles.css`**
   - **`shared.js`**
   - **`api-config.js`**

## 3. Point the frontend to the API

1. In **htdocs** on InfinityFree, **edit** `api-config.js`.
2. Set the API URL to your Render URL (no trailing slash):
   ```javascript
   window.API_BASE = "https://your-app-name.onrender.com";
   ```
3. Save.

## 4. Done

- Open your InfinityFree URL (e.g. `https://yoursite.epizy.com`). The site will load and all `/api/` requests will go to Render. Sign in (including Steam) and forums will work.
- **Steam login:** `BASE_URL` on Render must be your **Render** URL (so Steam redirects to the API). `FRONTEND_URL` must be your **InfinityFree** URL so after login users are sent back to your site.

## Notes

- **Render free tier:** the app may sleep after ~15 min idle; the first request after that can take ~1 min to wake.
- **Cookies:** Session cookies are set by Render; the browser sends them when your InfinityFree pages call the Render API because of `credentials: "include"` and `ALLOWED_ORIGIN`.
- **Same host (e.g. local):** leave `api-config.js` as `window.API_BASE = "";` so the frontend uses the same origin for the API.
