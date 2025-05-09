#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

# --- Configuration ---
# Get the absolute path of the directory where this script is run from
SCRIPT_DIR="$(pwd)"
REGISTRY_ENV_FILE="/app/registry/.env"
FININFO_ENV_FILE="/app/servers/fininfo/.env"
REGISTRY_ENV_TEMPLATE="/app/registry/.env.template"
EMBEDDINGS_MODEL_NAME="all-MiniLM-L6-v2"
EMBEDDINGS_MODEL_DIMENSIONS=384
FININFO_ENV_TEMPLATE="/app/servers/fininfo/.env.template"
NGINX_CONF_SRC="/app/docker/nginx_rev_proxy.conf"
NGINX_CONF_DEST="/etc/nginx/conf.d/nginx_rev_proxy.conf"

# --- Helper Functions ---
generate_secret_key() {
  python -c 'import secrets; print(secrets.token_hex(32))'
}

# --- Environment Variable Setup ---

# 1. Registry .env
echo "Setting up Registry environment ($REGISTRY_ENV_FILE)..."
# Use provided values or defaults/generated ones
SECRET_KEY_VALUE=${SECRET_KEY:-$(generate_secret_key)}
ADMIN_USER_VALUE=${ADMIN_USER:-admin}
ADMIN_PASSWORD_VALUE=${ADMIN_PASSWORD:-password} # Default password, recommend changing via env var

# Create .env file from template structure, substituting values
echo "SECRET_KEY=${SECRET_KEY_VALUE}" > "$REGISTRY_ENV_FILE"
echo "ADMIN_USER=${ADMIN_USER_VALUE}" >> "$REGISTRY_ENV_FILE"
echo "ADMIN_PASSWORD=${ADMIN_PASSWORD_VALUE}" >> "$REGISTRY_ENV_FILE"
echo "Registry .env created."
cat "$REGISTRY_ENV_FILE" # Print for verification

# 2. Fininfo Server .env
echo "Setting up Fininfo server environment ($FININFO_ENV_FILE)..."
# Use provided POLYGON_API_KEY or leave it empty (server handles missing key)
POLYGON_API_KEY_VALUE=${POLYGON_API_KEY:-}

# Create .env file from template structure
echo "POLYGON_API_KEY=${POLYGON_API_KEY_VALUE}" > "$FININFO_ENV_FILE"
echo "Fininfo .env created."
cat "$FININFO_ENV_FILE" # Print for verification

# --- Nginx Configuration ---
echo "Copying custom Nginx configuration..."
cp "$NGINX_CONF_SRC" "$NGINX_CONF_DEST"
echo "Nginx configuration copied to $NGINX_CONF_DEST."

# --- Start Background Services ---
export EMBEDDINGS_MODEL_NAME=$EMBEDDINGS_MODEL_NAME
export EMBEDDINGS_MODEL_DIMENSIONS=$EMBEDDINGS_MODEL_DIMENSIONS 

# 1. Start Example MCP Servers
echo "Starting example MCP servers in the background..."
cd /app
./start_all_servers.sh &
echo "MCP servers start command issued."
# Give servers a moment to initialize
sleep 5

# 2. Start MCP Registry
echo "Starting MCP Registry in the background..."
# Navigate to the registry directory to ensure relative paths work
cd /app/registry
# Use uv run to start uvicorn, ensuring it uses the correct environment
# Run on 0.0.0.0 to be accessible within the container network
# Use port 7860 as configured in nginx proxy_pass
source "$SCRIPT_DIR/.venv/bin/activate"
cd /app/registry && uvicorn main:app --host 0.0.0.0 --port 7860 &
echo "MCP Registry start command issued."
# Give registry a moment to initialize and generate initial nginx config
sleep 10

# --- Start Nginx in Background ---
echo "Starting Nginx in the background..."
# Start nginx normally, it will daemonize by default
nginx

echo "Nginx started. Keeping container alive..."
# Keep the container running indefinitely
tail -f /dev/null

echo "Entrypoint script finished." # This line will likely not be reached unless tail fails