# homeOS — imagem de produção
FROM node:20-bookworm-slim

# Ferramentas de build (fallback caso o better-sqlite3 precise compilar)
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ wget \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instala só as dependências de produção (cache eficiente)
COPY package*.json ./
RUN npm ci --omit=dev

# Copia o restante do código (ver .dockerignore)
COPY . .

ENV NODE_ENV=production
ENV PORT=3030
ENV DB_PATH=/data/data.db

EXPOSE 3030

# Healthcheck simples: a home page responde 200
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3030/ >/dev/null 2>&1 || exit 1

# Sem --env-file: as envs vêm do docker-compose
CMD ["node", "server.js"]
