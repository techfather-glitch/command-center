# Command Center — a single Node.js process, zero dependencies, no build step.
FROM node:22-alpine

WORKDIR /app
COPY server.js app.html package.json ./
COPY assets ./assets

# Persist settings, the encrypted vault and the audit log here (mount a volume).
ENV DATA_DIR=/app/data \
    PORT=8888 \
    NODE_ENV=production
# Runs as root so writes to a mounted data volume succeed regardless of which
# uid owns the host directory — a non-root container hit EACCES writing its
# vault/settings on common bind-mounts, silently preventing anything from saving.
# To run unprivileged instead, set `user: "<uid>:<gid>"` in compose (or --user)
# and make the data dir writable by that uid.
RUN mkdir -p /app/data

EXPOSE 8888

# Liveness: the unauthenticated meta endpoint returns 200 when the server is up.
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:${PORT}/api/meta >/dev/null 2>&1 || exit 1

CMD ["node", "server.js"]
