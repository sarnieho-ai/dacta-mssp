FROM node:20-slim
RUN npm install -g pnpm@9.15.0

WORKDIR /app

# Copy everything
COPY . .

# Install dependencies
RUN pnpm install

EXPOSE 3001
ENV NODE_ENV=production
ENV PORT=3001

CMD ["pnpm", "--filter", "@dacta/api", "start"]
