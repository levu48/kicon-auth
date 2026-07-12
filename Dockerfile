# syntax=docker/dockerfile:1

# ---- builder: install everything and compile TS -> dist ----
FROM node:20-slim AS builder
WORKDIR /app
# build tools for argon2's native addon (node-gyp fallback if no prebuilt)
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm ci
COPY tsconfig*.json nest-cli.json ./
COPY src ./src
RUN npm run build

# ---- runtime: slim image with prod deps + compiled output only ----
FROM node:20-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY package*.json ./
# reuse the already-built node_modules (argon2 native addon included), then
# drop devDependencies. Prod migrations run from compiled JS (no ts-node needed).
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
RUN npm prune --omit=dev && npm cache clean --force

USER node
EXPOSE 3000
# Readiness probe hits the app's /healthz (which checks Postgres + Redis).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://localhost:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/main.js"]
