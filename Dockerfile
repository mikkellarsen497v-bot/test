# Project New York — Node.js forum app
FROM node:20-alpine

WORKDIR /app

# Copy package files first for better layer caching
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# Copy app source (HTML, JS, CSS, data seed)
COPY . .

# Create data dir if not mounted (will be overridden by volume on Railway/Fly)
RUN mkdir -p /app/data

# Use persistent data when DATA_DIR is set (e.g. /data)
ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

CMD ["node", "server.js"]
