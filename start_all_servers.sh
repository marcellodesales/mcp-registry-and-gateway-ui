#!/bin/bash

# Get the absolute path of the directory where this script is run from
SCRIPT_DIR="$(pwd)"

# Set the base directory, logs directory, and starting port
SERVERS_DIR="$SCRIPT_DIR/servers"
LOGS_DIR="$SCRIPT_DIR/logs"
PORT_START=8001

# Check if servers directory exists
if [ ! -d "$SERVERS_DIR" ]; then
    echo "Error: '$SERVERS_DIR' directory does not exist."
    exit 1
fi

# Create logs directory if it doesn't exist
if [ ! -d "$LOGS_DIR" ]; then
    echo "Creating logs directory..."
    mkdir -p "$LOGS_DIR"
fi

# The virtual environment is now created and populated by the Dockerfile.
# We just need to ensure SCRIPT_DIR points to /app if this script is not run from /app
# Assuming SCRIPT_DIR will be /app based on WORKDIR and entrypoint execution context

# Activate the pre-built virtual environment
echo "Activating the pre-built virtual environment at $SCRIPT_DIR/.venv..."
source "$SCRIPT_DIR/.venv/bin/activate"

# Dependency installation is now handled by the Dockerfile.

# Find all subdirectories in the servers directory
subdirs=$(find "$SERVERS_DIR" -mindepth 1 -maxdepth 1 -type d | sort)

# Counter for port numbers
port=$PORT_START

# Process each subdirectory
for subdir in $subdirs; do
    # Extract the server name from the path
    server_name=$(basename "$subdir")
    echo "Processing directory: $subdir (port: $port, server: $server_name)"
    
    # Create log file paths with absolute paths
    log_file="$LOGS_DIR/${server_name}_${port}.log"
    pid_file="$LOGS_DIR/${server_name}_${port}.pid"
    
    # Move into the subdirectory
    cd "$subdir" || continue
    
    # Python environment setup is now global, so no local venv creation/activation needed here
    
    echo "Starting server on port $port (logs in $log_file)..."
    # Start the server in the background with the current port and redirect output to log file
    # uv run will use the globally activated venv
    uv run python server.py --port $port >> "$log_file" 2>&1 &
    
    # Store the process ID for potential cleanup later
    server_pid=$!
    echo "Server started with PID: $server_pid" | tee -a "$log_file"
    
    # Save PID to a file for easy management
    echo "$server_pid" > "$pid_file"
    
    # No local deactivation needed
    
    # Return to the original directory
    cd "$SCRIPT_DIR"
    
    # Increment the port number for the next server
    ((port++))
    
    echo "-----------------------------------"
done

# Deactivate the global virtual environment
echo "Deactivating the global virtual environment."
deactivate

echo "All servers have been started. Logs are available in the $LOGS_DIR directory."
echo "The shared virtual environment at $SCRIPT_DIR/.venv was used."
echo "To stop all servers, use: kill \$(cat $LOGS_DIR/*.pid)"
echo "To view logs in real-time for a specific server, use: tail -f $LOGS_DIR/server_name_port.log"