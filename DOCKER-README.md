# Docker Deployment Guide for Deuss Backend

This document explains how to deploy the Deuss application using Docker.

## Prerequisites

- Docker and Docker Compose installed on your system
- Git repository cloned

## Quick Start

1. Copy the example environment file and modify as needed:

```bash
cp .env.example .env
```

2. Build and start the containers:

```bash
docker-compose up -d
```

3. Initialize the database (first time only):

```bash
docker-compose exec app npm run setup-db
```

## Environment Variables

See `.env.example` for a list of required environment variables.

## Production Deployment

For production deployment:

1. Update all secret values in the `.env` file
2. Enable SSL/TLS with a reverse proxy (like Nginx or Traefik)
3. Use Docker Swarm or Kubernetes for orchestration

## Container Management

- View logs: `docker-compose logs -f app`
- Stop containers: `docker-compose down`
- Rebuild containers: `docker-compose up -d --build`

## Data Persistence

PostgreSQL data is stored in a Docker volume named `postgres_data`. 