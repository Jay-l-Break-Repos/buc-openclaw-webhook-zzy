FROM node:22-slim

WORKDIR /app

COPY repo/package.json ./

RUN npm install

COPY repo/ .

EXPOSE 9090

CMD ["node", "app.js"]
