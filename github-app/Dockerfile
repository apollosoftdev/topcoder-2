FROM node:20-slim

WORKDIR /app

# Install curl for healthcheck
# nosemgrep: dockerfile.security.missing-apt-get-clean.remove-package-cache
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY package*.json ./

# Install all dependencies (including devDependencies for build)
RUN npm install && npm cache clean --force

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Remove devDependencies after build
RUN npm prune --production

# Use existing node user (UID 1000)
RUN chown -R node:node /app
USER node

# Expose port
EXPOSE 3000

# Start the application
CMD ["npm", "start"]
