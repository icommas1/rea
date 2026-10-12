FROM node:24.21.0-bookworm-slim
ENV NODE_ENV=production \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH=/opt/venv/bin:$PATH
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv procps ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/venv
WORKDIR /app
COPY requirements.lock ./
RUN /opt/venv/bin/pip install --no-cache-dir -r requirements.lock
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force
COPY src ./src
COPY scripts ./scripts
COPY licenses ./licenses
RUN chmod 755 /app/scripts/limited-python
USER node
ENV PORT=8080
EXPOSE 8080
CMD ["node", "--max-old-space-size=128", "src/server.mjs"]
