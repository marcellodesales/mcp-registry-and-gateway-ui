# Use an official Python runtime as a parent image
FROM python:3.13-slim

# Set environment variables to prevent interactive prompts during installation
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install minimal system dependencies needed for the container to function
# All Python-related setup moved to entrypoint.sh for a more lightweight image
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

# Set the working directory in the container
WORKDIR /app

# Copy the application code
COPY . /app/

# Copy the custom Nginx configuration (will be moved by entrypoint)
# Note: We copy it here so it's part of the image layer
COPY docker/nginx_rev_proxy.conf /app/docker/nginx_rev_proxy.conf


# Make the entrypoint script executable
COPY docker/entrypoint.sh /app/docker/entrypoint.sh
RUN chmod +x /app/docker/entrypoint.sh

# Expose ports for Nginx (HTTP/HTTPS) and the Registry (direct access, though usually proxied)
EXPOSE 80 443 7860

# Run the entrypoint script when the container launches
ENTRYPOINT ["/app/docker/entrypoint.sh"]
