FROM node:24-slim
WORKDIR /app
COPY . .
RUN mkdir -p /data && chown -R node:node /data /app
ENV HOST=0.0.0.0 PORT=8080 DATA_DIR=/data
EXPOSE 8080
USER node
CMD ["node", "server.mjs"]
