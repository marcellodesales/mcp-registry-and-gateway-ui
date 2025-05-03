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
    
    echo "Setting up Python environment..."
    # Create a Python virtual environment using uv
    uv venv --python 3.12
    
    # Activate the virtual environment
    source .venv/bin/activate
    
    echo "Installing requirements in $(pwd)..."
    # Install requirements from pyproject.toml
    if [ -f "pyproject.toml" ]; then
        uv pip install --requirement pyproject.toml >> "$log_file" 2>&1
    else
        echo "Warning: pyproject.toml not found in $subdir" | tee -a "$log_file"
    fi
    
    echo "Starting server on port $port (logs in $log_file)..."
    # Start the server in the background with the current port and redirect output to log file
    uv run python server.py --port $port >> "$log_file" 2>&1 &
    
    # Store the process ID for potential cleanup later
    server_pid=$!
    echo "Server started with PID: $server_pid" | tee -a "$log_file"
    
    # Save PID to a file for easy management
    echo "$server_pid" > "$pid_file"
    
    # Deactivate the virtual environment
    deactivate
    
    # Return to the original directory
    cd "$SCRIPT_DIR"
    
    # Increment the port number for the next server
    ((port++))
    
    echo "-----------------------------------"
done

echo "All servers have been started. Logs are available in the $LOGS_DIR directory."
echo "To stop all servers, use: kill \$(cat $LOGS_DIR/*.pid)"
echo "To view logs in real-time for a specific server, use: tail -f $LOGS_DIR/server_name_port.log"