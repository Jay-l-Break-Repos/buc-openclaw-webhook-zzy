FROM node:22-slim

WORKDIR /app

COPY repo/package.json repo/package-lock.json ./

RUN npm ci

COPY repo/ .

EXPOSE 9090

CMD ["node", "app.js"]
