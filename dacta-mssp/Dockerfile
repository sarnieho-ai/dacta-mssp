FROM node:22-slim AS base
RUN npm install -g pnpm@9.15.0

WORKDIR /app

# Copy workspace config
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml* tsconfig.base.json ./

# Copy package.jsons for all workspace packages
COPY packages/shared/package.json packages/shared/
COPY apps/api/package.json apps/api/

# Install dependencies
RUN pnpm install --frozen-lockfile || pnpm install

# Copy source
COPY packages/shared/ packages/shared/
COPY apps/api/ apps/api/

# Build shared package first, then API
RUN cd packages/shared && pnpm build
RUN cd apps/api && pnpm build

# Production stage
FROM node:22-slim
RUN npm install -g pnpm@9.15.0

WORKDIR /app

COPY --from=base /app/package.json /app/pnpm-workspace.yaml ./
COPY --from=base /app/packages/shared/package.json packages/shared/
COPY --from=base /app/packages/shared/dist packages/shared/dist/
COPY --from=base /app/apps/api/package.json apps/api/
COPY --from=base /app/apps/api/dist apps/api/dist/
COPY --from=base /app/node_modules node_modules/
COPY --from=base /app/apps/api/node_modules apps/api/node_modules/
COPY --from=base /app/packages/shared/node_modules packages/shared/node_modules/

EXPOSE 3001

ENV NODE_ENV=production
ENV PORT=3001

CMD ["node", "apps/api/dist/index.js"]
