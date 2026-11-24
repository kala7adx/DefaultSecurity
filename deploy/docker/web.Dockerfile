# Skyline web UI (Next.js standalone server). Build from the repo root:
#   docker build -f deploy/docker/web.Dockerfile .
#
# The browser only talks to this server; /api/v1/* is proxied to the API service, whose
# address is fixed at build time (Next.js bakes rewrites into the build).

FROM node:26-bookworm-slim@sha256:b822af76043e2656ffc172072036fe0968a3c09a692e4ad05eb9348ad5dbdf4c AS build
ARG SKYLINE_API_ORIGIN=http://api:8000
# pnpm, verified against a pinned SHA-512 before installing (matches the registry integrity).
ARG PNPM_VERSION=12.21.0
ARG PNPM_SHA512=66fd8278ee28935ce951792d34367ff3af5c432a2756445823029533835b8da529bbe0be5130afd56ed0713fb8789e47bad82d93bd5ae2fe54b15562d6276ef0
ENV NEXT_TELEMETRY_DISABLED=1 \
    SKYLINE_API_ORIGIN=${SKYLINE_API_ORIGIN}
WORKDIR /tmp/pnpm
RUN npm pack "pnpm@${PNPM_VERSION}" --silent \
    && echo "${PNPM_SHA512}  pnpm-${PNPM_VERSION}.tgz" | sha512sum -c - \
    && npm install --global --ignore-scripts "./pnpm-${PNPM_VERSION}.tgz"
WORKDIR /src
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web/package.json ./apps/web/
RUN pnpm install --frozen-lockfile --filter @skyline/web
COPY apps/web ./apps/web
RUN pnpm --dir apps/web build

FROM node:26-bookworm-slim@sha256:b822af76043e2656ffc172072036fe0968a3c09a692e4ad05eb9348ad5dbdf4c AS web
# No package managers at runtime (npm's own dependencies show up in image scans).
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
           /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /opt/yarn-* \
           /usr/local/bin/yarn /usr/local/bin/yarnpkg
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
WORKDIR /app
# Root-owned code: the runtime user can read it but not change it (the build cache is tmpfs).
COPY --from=build /src/apps/web/.next/standalone ./
COPY --from=build /src/apps/web/.next/static ./apps/web/.next/static
USER node
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD ["node", "-e", "fetch('http://127.0.0.1:3000/login').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "apps/web/server.js"]
