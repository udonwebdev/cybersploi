FROM node:18-alpine

WORKDIR /app

RUN apk add --no-cache curl python3 make g++

COPY package*.json ./
COPY prisma ./prisma/

RUN npm install
RUN npx prisma generate

COPY . .

EXPOSE 8000

ENV PORT=8000
ENV NODE_ENV=production

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["node", "server.js"]
