FROM node:18-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY . .
# Hugging Face Spaces expects 7860, Koyeb/Render/Railway use PORT — server.js respects PORT env
EXPOSE 7860
EXPOSE 8080
CMD ["node", "server.js"]
