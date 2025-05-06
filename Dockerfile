FROM node:18-alpine

# Create app directory
WORKDIR /usr/src/app

# Install pnpm globally
RUN npm install -g pnpm


# Copy package.json and pnpm-lock.yaml
COPY package.json pnpm-lock.yaml schema-manager.js ./

# Install dependencies
RUN pnpm install --frozen-lockfile


# Copy application code
COPY . .

# Set environment variables
ENV NODE_ENV=development
ENV PORT=3002
ENV PGSSLMODE=disable
ENV DATABASE_URL=postgres://postgres:postgres@db:5432/deuss_db
# Expose port
EXPOSE 3002

# Run the application
CMD ["pnpm", "run", "update-schema"]
