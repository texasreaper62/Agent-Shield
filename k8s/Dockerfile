FROM node:20-alpine

LABEL maintainer="Agent Shield <https://github.com/texasreaper62/Agent-Shield>"
LABEL description="Agent Shield sidecar — local threat detection for AI agent pods"

WORKDIR /app

# Copy package manifest and install production dependencies
COPY package.json ./
RUN npm install --production --ignore-scripts && npm cache clean --force

# Copy the detection engine
COPY src/ ./src/

# Copy the sidecar server
COPY k8s/server.js ./server.js

# Non-root user for security
RUN addgroup -S shield && adduser -S shield -G shield
USER shield

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -q --spider http://localhost:8080/health || exit 1

CMD ["node", "server.js"]
