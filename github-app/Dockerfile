FROM node:20-alpine

LABEL maintainer="Agent Shield"
LABEL description="Agent Shield GitHub App — PR prompt injection scanner"

WORKDIR /app

# Copy application files (zero dependencies, no npm install needed)
COPY *.js ./

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

CMD ["node", "app.js"]
