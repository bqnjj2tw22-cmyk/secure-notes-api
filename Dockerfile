# --- build stage -------------------------------------------------------------
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY src ./src

# --- runtime stage -----------------------------------------------------------
FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app

# Run as an unprivileged user; never as root.
RUN addgroup -S app && adduser -S -G app app

COPY --from=build --chown=app:app /app/node_modules ./node_modules
COPY --chown=app:app package.json ./
COPY --chown=app:app src ./src

USER app
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD wget -qO- http://127.0.0.1:3000/health || exit 1

CMD ["node", "src/server.js"]
