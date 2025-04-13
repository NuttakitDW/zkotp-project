FROM node:18

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .

# Cloud Run will assign a PORT env var; your code must listen on that port.
EXPOSE 8080

CMD ["npm", "start"]