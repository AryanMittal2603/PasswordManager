# --- build stage: compile native deps (better-sqlite3) ---
FROM node:20-bookworm-slim AS build
WORKDIR /app
# Toolchain needed to build better-sqlite3 if no prebuilt binary matches.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .

# --- runtime stage: slim image, no build tools, non-root ---
FROM node:20-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package*.json ./
COPY --from=build /app/src ./src
COPY --from=build /app/public ./public

# Persisted database lives here; mount a volume at /app/data.
RUN mkdir -p /app/data && chown -R node:node /app
USER node
VOLUME ["/app/data"]
EXPOSE 3000
CMD ["node", "src/server.js"]
