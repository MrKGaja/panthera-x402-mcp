FROM node:20-alpine

WORKDIR /app

COPY package.json ./
COPY index.js ./
COPY src ./src

ENV NODE_ENV=production

ENTRYPOINT ["node", "index.js"]
