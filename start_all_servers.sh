#!/bin/bash

# Set the base directory and starting port
SERVERS_DIR="servers"
PORT_START=8001

# Check if servers directory exists
if [ ! -d "$SERVERS_DIR" ]; then
    echo "Error: '$SERVERS_DIR' directory does not exist."
    exit 1
fi

# Find all subdirectories in the servers directory
subdirs=$(find "$SERVERS_DIR" -mindepth 1 -maxdepth 1 -type d | sort)

# Counter for port numbers
port=$PORT_START

# Process each subdirectory
for subdir in $subdirs; do
    echo "Processing directory: $subdir (port: $port)"
    
    # Move into the subdirectory
    cd "$subdir" || continue
    
    echo "Setting up Python environment..."
    # Create a Python virtual environment using uv
    uv venv --python 3.12
    
    # Activate the virtual environment
    source .venv/bin/activate
    
    echo "Installing requirements..."
    # Install requirements from pyproject.toml
    if [ -f "pyproject.toml" ]; then
        uv pip install --requirement pyproject.toml
    else
        echo "Warning: pyproject.toml not found in $subdir"
    fi
    
    echo "Starting server on port $port..."
    # Start the server in the background with the current port
    uv run python server.py --port $port &
    
    # Store the process ID for potential cleanup later
    echo "Server started with PID: $!"
    
    # Deactivate the virtual environment
    deactivate
    
    # Return to the parent directory
    cd - > /dev/null
    
    # Increment the port number for the next server
    ((port++))
    
    echo "-----------------------------------"
done

echo "All servers have been started."
echo "To stop the servers, use: kill \$(ps aux | grep 'python server.py' | grep -v grep | awk '{print \$2}')"