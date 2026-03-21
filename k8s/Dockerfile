FROM node:20-alpine

LABEL maintainer="Agent Shield <https://github.com/texasreaper62/Agent-Shield>"
LABEL description="Agent Shield sidecar - local threat detection for AI agent pods"

WORKDIR /app

# Non-root user for security (create before COPY so files are owned correctly)
RUN addgroup -S shield && adduser -S shield -G shield

# Copy package manifest and install production dependencies
COPY --chown=shield:shield package.json ./
RUN npm install --production --ignore-scripts && npm cache clean --force

# Copy the detection engine and sidecar server
COPY --chown=shield:shield src/ ./src/
COPY --chown=shield:shield k8s/server.js ./server.js

USER shield

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -q --spider http://localhost:8080/health || exit 1

CMD ["node", "server.js"]
