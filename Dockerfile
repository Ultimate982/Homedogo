FROM node:22-slim
WORKDIR /app
COPY . .
ENV NODE_ENV=production DATA_DIR=/data PORT=3000
VOLUME /data
EXPOSE 3000
CMD ["node","server.js"]
