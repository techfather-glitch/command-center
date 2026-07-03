# Command Center — a single Node.js process, zero dependencies, no build step.
FROM node:22-alpine

# Run as a non-root user.
RUN addgroup -S cc && adduser -S cc -G cc

WORKDIR /app
COPY server.js app.html ./
COPY assets ./assets

# Persist settings, the encrypted vault and the audit log here (mount a volume).
ENV DATA_DIR=/app/data \
    PORT=8888 \
    NODE_ENV=production
RUN mkdir -p /app/data && chown -R cc:cc /app
USER cc

EXPOSE 8888

# Liveness: the unauthenticated meta endpoint returns 200 when the server is up.
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:${PORT}/api/meta >/dev/null 2>&1 || exit 1

CMD ["node", "server.js"]
