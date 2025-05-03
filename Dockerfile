# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set environment variables to prevent interactive prompts during installation
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies: nginx, curl (for health checks in registry), procps (for ps command used in stop script), openssl (for cert generation), git (needed by uv sometimes), build-essential (for potential C extensions), sudo (for sudo command)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    curl \
    procps \
    openssl \
    git \
    build-essential \
    sudo \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install uv globally using pip
RUN pip install uv

# Set the working directory in the container
WORKDIR /app

# Copy the entire project context into the container
COPY . /app/

# Install Python dependencies for the MCP Registry using uv
# The server dependencies will be installed by start_all_servers.sh at runtime
RUN cd /app && uv pip install --system --requirement pyproject.toml

# Generate self-signed SSL certificate for Nginx
# Create directories for SSL certs
RUN mkdir -p /etc/ssl/certs /etc/ssl/private
# Generate the certificate and key
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/privkey.pem \
    -out /etc/ssl/certs/fullchain.pem \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=localhost"

# Copy the custom Nginx configuration (will be moved by entrypoint)
# Note: We copy it here so it's part of the image layer
COPY docker/nginx_rev_proxy.conf /app/docker/nginx_rev_proxy.conf


# Make the entrypoint script executable
COPY docker/entrypoint.sh /app/docker/entrypoint.sh
RUN chmod +x /app/docker/entrypoint.sh

# Expose ports for Nginx (HTTP/HTTPS) and the Registry (direct access, though usually proxied)
EXPOSE 80 443 7860

# Define environment variables for registry/server configuration (can be overridden at runtime)
# Provide sensible defaults or leave empty if they should be explicitly set
ARG SECRET_KEY=""
ARG ADMIN_USER="admin"
ARG ADMIN_PASSWORD="password"
ARG POLYGON_API_KEY=""

ENV SECRET_KEY=$SECRET_KEY
ENV ADMIN_USER=$ADMIN_USER
ENV ADMIN_PASSWORD=$ADMIN_PASSWORD
ENV POLYGON_API_KEY=$POLYGON_API_KEY

# Run the entrypoint script when the container launches
ENTRYPOINT ["/app/docker/entrypoint.sh"]