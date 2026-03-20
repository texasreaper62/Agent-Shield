FROM node:22-alpine AS base
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev && npm cache clean --force

FROM node:22-alpine
WORKDIR /app
RUN addgroup -g 1001 shield && adduser -u 1001 -G shield -s /bin/sh -D shield
COPY --from=base /app/node_modules ./node_modules
COPY src/ ./src/
COPY bin/ ./bin/
COPY package.json ./
USER shield
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', r => process.exit(r.statusCode === 200 ? 0 : 1))"
ENTRYPOINT ["node", "bin/agent-shield.js"]
CMD ["serve"]
