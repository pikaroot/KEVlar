# syntax=docker/dockerfile:1

# =============================================================================
# KEVlar — production image for a Next.js 15 app (App Router, standalone output)
#
# Multi-stage build:
#   deps    → install node_modules from the lockfile
#   builder → compile the app (produces .next/standalone + .next/static)
#   runner  → minimal runtime that runs `node server.js` as a non-root user
#
# Build:  docker build -t kevlar .
# Run:    docker run -p 3000:3000 -e NVD_API_KEY=xxxx kevlar
# =============================================================================

# ---- deps: install dependencies -------------------------------------------
FROM node:22-alpine AS deps
WORKDIR /app
# libc6-compat helps some native deps run on Alpine's musl libc.
RUN apk add --no-cache libc6-compat
COPY package.json package-lock.json ./
RUN npm ci

# ---- builder: build the Next.js app ---------------------------------------
FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# Don't send anonymous telemetry from CI/build environments.
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# ---- runner: the final, slim runtime image --------------------------------
FROM node:22-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
# server.js honours these; bind to all interfaces so the container is reachable.
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

# Run as an unprivileged user.
RUN addgroup --system --gid 1001 nodejs \
  && adduser --system --uid 1001 nextjs

# The standalone output already contains the trimmed node_modules and server.js.
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public ./public

USER nextjs
EXPOSE 3000

# Simple liveness check against the home page (wget ships with Alpine busybox).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/ || exit 1

CMD ["node", "server.js"]
