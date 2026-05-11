# syntax=docker/dockerfile:1.7
# -----------------------------------------------------------------------------
# Agent Shield - production container
# Multi-stage build, runs the zero-dependency HTTP sidecar on port 3000.
# -----------------------------------------------------------------------------

FROM node:22-alpine AS builder
WORKDIR /app

# Install production dependencies only.
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

# -----------------------------------------------------------------------------
FROM node:22-alpine
WORKDIR /app

# Non-root user for runtime.
RUN addgroup -g 1001 shield && adduser -u 1001 -G shield -s /bin/sh -D shield

# Copy production deps from builder.
COPY --from=builder --chown=shield:shield /app/node_modules ./node_modules

# Copy the runtime surface: SDK source, CLI, sidecar server, types, package manifest.
COPY --chown=shield:shield package.json ./
COPY --chown=shield:shield src/ ./src/
COPY --chown=shield:shield bin/ ./bin/
COPY --chown=shield:shield sidecar/ ./sidecar/
COPY --chown=shield:shield types/ ./types/

ENV NODE_ENV=production
ENV PORT=3000

USER shield

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:'+(process.env.PORT||3000)+'/health', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

# Run the sidecar HTTP server. Override with `docker run ... <command>` for CLI usage.
CMD ["node", "sidecar/server.js"]

# -----------------------------------------------------------------------------
# OCI image metadata
# -----------------------------------------------------------------------------
LABEL org.opencontainers.image.title="Agent Shield"
LABEL org.opencontainers.image.description="SOTA security SDK for AI agents - prompt injection, data exfiltration, tool poisoning, and 40+ AI-specific threats. Zero dependencies, local-only detection."
LABEL org.opencontainers.image.source="https://github.com/texasreaper62/Agent-Shield"
LABEL org.opencontainers.image.url="https://github.com/texasreaper62/Agent-Shield"
LABEL org.opencontainers.image.documentation="https://github.com/texasreaper62/Agent-Shield#readme"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.version="14.2.0"
LABEL org.opencontainers.image.vendor="texasreaper62"
LABEL org.opencontainers.image.authors="texasreaper62"
