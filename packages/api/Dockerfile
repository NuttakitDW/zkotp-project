# 1) Use an official Node LTS image as the base
FROM node:18

# 2) Set the working directory in the container
WORKDIR /usr/src/app

# 3) Copy package.json and package-lock.json
COPY package*.json ./

# 4) Install dependencies (npm ci if you want a clean install)
RUN npm install

# 5) Copy the rest of your application code
COPY . .
COPY utils/*.wasm /usr/src/app/utils/
COPY utils/*.zkey /usr/src/app/utils/
COPY utils/*.json /usr/src/app/utils/
RUN ls -l /usr/src/app/utils


# 6) Expose the port your API listens on (optional, for clarity)
EXPOSE 3000

# 7) Command to start your API
CMD ["npm", "start"]
