/**
 * PM2 config for VPS — run: pm2 start ecosystem.config.cjs
 * See DEPLOY.md for full VPS setup.
 */
module.exports = {
  apps: [
    {
      name: "pny",
      script: "server.js",
      cwd: __dirname,
      instances: 1,
      exec_mode: "fork",
      env: {
        NODE_ENV: "production",
      },
      env_production: {
        NODE_ENV: "production",
      },
    },
  ],
};
