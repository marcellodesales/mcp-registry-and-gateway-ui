import os
import re
import json
import secrets
import asyncio
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path  # Import Path
from typing import Annotated, List, Set
from datetime import datetime, timezone, timedelta

from fastapi import (
    FastAPI,
    Request,
    Depends,
    HTTPException,
    Form,
    status,
    Cookie,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from dotenv import load_dotenv
import subprocess # Added for nginx reload

# --- MCP Client Imports --- START
from mcp import ClientSession
from mcp.client.sse import sse_client
# --- MCP Client Imports --- END

# Determine the base directory of this script (registry folder)
BASE_DIR = Path(__file__).resolve().parent

load_dotenv(dotenv_path=BASE_DIR.parent / ".env")  # Load .env from parent directory

# --- Configuration & State (Paths relative to this script) ---
NGINX_CONFIG_PATH = (
    BASE_DIR / "nginx_mcp_revproxy.conf"
)  # In the same folder as main.py
SERVERS_DIR = BASE_DIR / "servers"  # Directory to store individual server JSON files
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"
NGINX_TEMPLATE_PATH = BASE_DIR / "nginx_template.conf" # Path to the template
STATE_FILE_PATH = BASE_DIR / "server_state.json" # Path to store enabled/disabled state

# In-memory state store
REGISTERED_SERVERS = {}
MOCK_SERVICE_STATE = {}
SERVER_HEALTH_STATUS = {} # Added for health check status: path -> 'healthy' | 'unhealthy' | 'checking' | 'error: <msg>'
HEALTH_CHECK_INTERVAL_SECONDS = 300 # Check every 5 minutes (restored)
HEALTH_CHECK_TIMEOUT_SECONDS = 10  # Timeout for each curl check (Increased to 10)
SERVER_LAST_CHECK_TIME = {} # path -> datetime of last check attempt (UTC)

# --- WebSocket Connection Management ---
active_connections: Set[WebSocket] = set()

async def broadcast_health_status():
    """Sends the current health status to all connected WebSocket clients."""
    if active_connections:
        print(f"Broadcasting health status to {len(active_connections)} clients...")

        # Construct data payload with status and ISO timestamp string
        data_to_send = {}
        for path, status in SERVER_HEALTH_STATUS.items():
            last_checked_dt = SERVER_LAST_CHECK_TIME.get(path)
            # Send ISO string or None
            last_checked_iso = last_checked_dt.isoformat() if last_checked_dt else None
            # Get the current tool count from REGISTERED_SERVERS
            num_tools = REGISTERED_SERVERS.get(path, {}).get("num_tools", 0) # Default to 0 if not found

            data_to_send[path] = {
                "status": status,
                "last_checked_iso": last_checked_iso, # Changed key
                "num_tools": num_tools # --- Add num_tools --- START
            }
            # --- Add num_tools --- END

        message = json.dumps(data_to_send)

        # Keep track of connections that fail during send
        disconnected_clients = set()

        # Iterate over a copy of the set to allow modification during iteration
        current_connections = list(active_connections)

        # Create send tasks and associate them with the connection
        send_tasks = []
        for conn in current_connections:
            send_tasks.append((conn, conn.send_text(message)))

        # Run tasks concurrently and check results
        results = await asyncio.gather(*(task for _, task in send_tasks), return_exceptions=True)

        for i, result in enumerate(results):
            conn, _ = send_tasks[i] # Get the corresponding connection
            if isinstance(result, Exception):
                # Check if it's a connection-related error (more specific checks possible)
                # For now, assume any exception during send means the client is gone
                print(f"Error sending to WebSocket client {conn.client}: {result}. Marking for removal.")
                disconnected_clients.add(conn)

        # Remove all disconnected clients identified during the broadcast
        if disconnected_clients:
            print(f"Removing {len(disconnected_clients)} disconnected clients after broadcast.")
            for conn in disconnected_clients:
                if conn in active_connections:
                    active_connections.remove(conn)

# Session management configuration
SECRET_KEY = os.environ.get("SECRET_KEY", "insecure-default-key-for-testing-only")
if SECRET_KEY == "insecure-default-key-for-testing-only":
    print(
        "\nWARNING: Using insecure default SECRET_KEY. Set a strong SECRET_KEY environment variable for production.\n"
    )
SESSION_COOKIE_NAME = "mcp_gateway_session"
signer = URLSafeTimedSerializer(SECRET_KEY)
SESSION_MAX_AGE_SECONDS = 60 * 60 * 8  # 8 hours

# --- Nginx Config Generation ---

LOCATION_BLOCK_TEMPLATE = """
    location {path} {{
        proxy_pass {proxy_pass_url};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }}
"""

COMMENTED_LOCATION_BLOCK_TEMPLATE = """
#    location {path} {{
#        proxy_pass {proxy_pass_url};
#        proxy_http_version 1.1;
#        proxy_set_header Host $host;
#        proxy_set_header X-Real-IP $remote_addr;
#        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#    }}
"""

def regenerate_nginx_config():
    """Generates the nginx config file based on registered servers and their state."""
    print(f"Regenerating Nginx config at {NGINX_CONFIG_PATH}...")
    try:
        with open(NGINX_TEMPLATE_PATH, 'r') as f_template:
            template_content = f_template.read()

        location_blocks = []
        sorted_paths = sorted(REGISTERED_SERVERS.keys())

        for path in sorted_paths:
            server_info = REGISTERED_SERVERS[path]
            proxy_url = server_info.get("proxy_pass_url")
            is_enabled = MOCK_SERVICE_STATE.get(path, False) # Default to disabled if state unknown
            health_status = SERVER_HEALTH_STATUS.get(path) # Get current health status

            if not proxy_url:
                print(f"Warning: Skipping server '{server_info['server_name']}' ({path}) - missing proxy_pass_url.")
                continue

            # Only create an active block if the service is enabled AND healthy
            if is_enabled and health_status == "healthy":
                block = LOCATION_BLOCK_TEMPLATE.format(
                    path=path,
                    proxy_pass_url=proxy_url
                )
            else:
                # Comment out the block if disabled OR not healthy
                block = COMMENTED_LOCATION_BLOCK_TEMPLATE.format(
                    path=path,
                    proxy_pass_url=proxy_url
                )
            location_blocks.append(block)

        final_config = template_content.replace("# {{LOCATION_BLOCKS}}", "\n".join(location_blocks))

        with open(NGINX_CONFIG_PATH, 'w') as f_out:
            f_out.write(final_config)
        print("Nginx config regeneration successful.")

        # --- Reload Nginx --- START
        try:
            print("Attempting to reload Nginx configuration...")
            # Ensure nginx command is available in PATH and process has permissions
            result = subprocess.run(['nginx', '-s', 'reload'], check=True, capture_output=True, text=True)
            print(f"Nginx reload successful. Output:\n{result.stdout}")
            # --- Reload Nginx --- END
            return True # Return True only if write AND reload succeed
        except FileNotFoundError:
             print("ERROR: 'nginx' command not found. Cannot reload configuration.")
             return False # Indicate failure if nginx command isn't found
        except subprocess.CalledProcessError as e:
             print(f"ERROR: Failed to reload Nginx configuration. Return code: {e.returncode}")
             print(f"Stderr: {e.stderr}")
             print(f"Stdout: {e.stdout}")
             return False # Indicate failure on reload error
        except Exception as e: # Catch other potential exceptions like permission errors
             print(f"ERROR: An unexpected error occurred during Nginx reload: {e}")
             return False # Indicate failure

    except FileNotFoundError:
        print(f"ERROR: Nginx template file not found at {NGINX_TEMPLATE_PATH}")
        return False
    except Exception as e:
        print(f"ERROR: Failed to regenerate Nginx config: {e}")
        return False

# --- Helper function to normalize a path to a filename ---
def path_to_filename(path):
    # Remove leading slash and replace remaining slashes with underscores
    normalized = path.lstrip("/").replace("/", "_")
    # Append .json extension if not present
    if not normalized.endswith(".json"):
        normalized += ".json"
    return normalized


# --- Data Loading ---
def load_registered_servers_and_state():
    global REGISTERED_SERVERS, MOCK_SERVICE_STATE
    print(f"Loading server definitions from {SERVERS_DIR}...")

    # Create servers directory if it doesn't exist
    SERVERS_DIR.mkdir(exist_ok=True)

    temp_servers = {}
    server_files = list(SERVERS_DIR.glob("*.json"))

    if not server_files:
        print(f"No server definition files found in {SERVERS_DIR}.")
        REGISTERED_SERVERS = {}
        return

    for server_file in server_files:
        try:
            with open(server_file, "r") as f:
                server_info = json.load(f)

                if (
                    isinstance(server_info, dict)
                    and "path" in server_info
                    and "server_name" in server_info
                ):
                    server_path = server_info["path"]
                    if server_path in temp_servers:
                        print(
                            f"Warning: Duplicate server path found in {server_file}: {server_path}. Overwriting previous definition."
                        )

                    # Add new fields with defaults
                    server_info["description"] = server_info.get("description", "")
                    server_info["tags"] = server_info.get("tags", [])
                    server_info["num_tools"] = server_info.get("num_tools", 0)
                    server_info["num_stars"] = server_info.get("num_stars", 0)
                    server_info["is_python"] = server_info.get("is_python", False)
                    server_info["license"] = server_info.get("license", "N/A")
                    server_info["proxy_pass_url"] = server_info.get("proxy_pass_url", None)
                    server_info["tool_list"] = server_info.get("tool_list", []) # Initialize tool_list if missing

                    temp_servers[server_path] = server_info
                else:
                    print(
                        f"Warning: Invalid server entry format found in {server_file}. Skipping."
                    )
        except FileNotFoundError:
            print(f"ERROR: Server definition file not found at {server_file}.")
        except json.JSONDecodeError as e:
            print(f"ERROR: Could not parse JSON from {server_file}: {e}.")
        except Exception as e:
            print(f"ERROR: An unexpected error occurred loading {server_file}: {e}.")

    REGISTERED_SERVERS = temp_servers
    print(
        f"Successfully loaded {len(REGISTERED_SERVERS)} servers from individual files."
    )

    # --- Load persisted mock service state --- START
    print(f"Attempting to load persisted state from {STATE_FILE_PATH}...")
    loaded_state = {}
    try:
        if STATE_FILE_PATH.exists():
            with open(STATE_FILE_PATH, "r") as f:
                loaded_state = json.load(f)
            if not isinstance(loaded_state, dict):
                print(f"Warning: Invalid state format in {STATE_FILE_PATH}. Expected a dictionary. Ignoring.")
                loaded_state = {} # Reset if format is wrong
            else:
                print("Successfully loaded persisted state.")
        else:
            print("No persisted state file found. Initializing state.")

    except json.JSONDecodeError as e:
        print(f"ERROR: Could not parse JSON from {STATE_FILE_PATH}: {e}. Initializing state.")
        loaded_state = {}
    except Exception as e:
        print(f"ERROR: Failed to read state file {STATE_FILE_PATH}: {e}. Initializing state.")
        loaded_state = {}

    # Initialize MOCK_SERVICE_STATE: Use loaded state if valid, otherwise default to False.
    # Ensure state only contains keys for currently registered servers.
    MOCK_SERVICE_STATE = {}
    for path in REGISTERED_SERVERS.keys():
        MOCK_SERVICE_STATE[path] = loaded_state.get(path, False) # Default to False if not in loaded state or state was invalid

    print(f"Final initial mock state: {MOCK_SERVICE_STATE}")
    # --- Load persisted mock service state --- END


    # Initialize health status to 'checking' or 'disabled' based on the just loaded state
    global SERVER_HEALTH_STATUS
    SERVER_HEALTH_STATUS = {} # Start fresh
    for path, is_enabled in MOCK_SERVICE_STATE.items():
        if path in REGISTERED_SERVERS: # Should always be true here now
            SERVER_HEALTH_STATUS[path] = "checking" if is_enabled else "disabled"
        else:
             # This case should ideally not happen if MOCK_SERVICE_STATE is built from REGISTERED_SERVERS
             print(f"Warning: Path {path} found in loaded state but not in registered servers. Ignoring.")

    print(f"Initialized health status based on loaded state: {SERVER_HEALTH_STATUS}")

    # We no longer need the explicit default initialization block below
    # print("Initializing mock service state (defaulting to disabled)...")
    # MOCK_SERVICE_STATE = {path: False for path in REGISTERED_SERVERS.keys()}
    # # TODO: Consider loading initial state from a persistent store if needed
    # print(f"Initial mock state: {MOCK_SERVICE_STATE}")


# --- Helper function to save server data ---
def save_server_to_file(server_info):
    try:
        # Create servers directory if it doesn't exist
        SERVERS_DIR.mkdir(exist_ok=True)

        # Generate filename based on path
        path = server_info["path"]
        filename = path_to_filename(path)
        file_path = SERVERS_DIR / filename

        with open(file_path, "w") as f:
            json.dump(server_info, f, indent=2)

        print(
            f"Successfully saved server '{server_info['server_name']}' to {file_path}"
        )
        return True
    except Exception as e:
        print(f"ERROR: Failed to save server data to {filename}: {e}")
        return False


# --- MCP Client Function to Get Tool List --- START (Renamed)
async def get_tools_from_server(base_url: str) -> List[dict] | None: # Return list of dicts
    """
    Connects to an MCP server via SSE, lists tools, and returns their details
    (name, description, schema).

    Args:
        base_url: The base URL of the MCP server (e.g., http://localhost:8000).

    Returns:
        A list of tool detail dictionaries (keys: name, description, schema),
        or None if connection/retrieval fails.
    """
    # Determine scheme and construct the full /sse URL
    if not base_url:
        print("MCP Check Error: Base URL is empty.")
        return None

    sse_url = base_url.rstrip('/') + "/sse"
    # Simple check for https, might need refinement for edge cases
    secure_prefix = "s" if sse_url.startswith("https://") else ""
    mcp_server_url = f"http{secure_prefix}://{sse_url[len(f'http{secure_prefix}://'):]}" # Ensure correct format for sse_client


    print(f"Attempting to connect to MCP server at {mcp_server_url} to get tool list...")
    try:
        # Connect using the sse_client context manager directly
        async with sse_client(mcp_server_url) as (read, write):
             # Use the ClientSession context manager directly
            async with ClientSession(read, write, sampling_callback=None) as session:
                # Apply timeout to individual operations within the session
                await asyncio.wait_for(session.initialize(), timeout=10.0) # Timeout for initialize
                tools_response = await asyncio.wait_for(session.list_tools(), timeout=15.0) # Renamed variable

                # Extract tool details
                tool_details_list = []
                if tools_response and hasattr(tools_response, 'tools'):
                    for tool in tools_response.tools:
                        # Access attributes directly based on MCP documentation
                        tool_name = getattr(tool, 'name', 'Unknown Name') # Direct attribute access
                        tool_desc = getattr(tool, 'description', None) or getattr(tool, '__doc__', None)

                        # --- Parse Docstring into Sections --- START
                        parsed_desc = {
                            "main": "No description available.",
                            "args": None,
                            "returns": None,
                            "raises": None,
                        }
                        if tool_desc:
                            tool_desc = tool_desc.strip()
                            # Simple parsing logic (can be refined)
                            lines = tool_desc.split('\n')
                            main_desc_lines = []
                            current_section = "main"
                            section_content = []

                            for line in lines:
                                stripped_line = line.strip()
                                if stripped_line.startswith("Args:"):
                                    parsed_desc["main"] = "\n".join(main_desc_lines).strip()
                                    current_section = "args"
                                    section_content = [stripped_line[len("Args:"):].strip()]
                                elif stripped_line.startswith("Returns:"):
                                    if current_section != "main": parsed_desc[current_section] = "\n".join(section_content).strip()
                                    else: parsed_desc["main"] = "\n".join(main_desc_lines).strip()
                                    current_section = "returns"
                                    section_content = [stripped_line[len("Returns:"):].strip()]
                                elif stripped_line.startswith("Raises:"):
                                    if current_section != "main": parsed_desc[current_section] = "\n".join(section_content).strip()
                                    else: parsed_desc["main"] = "\n".join(main_desc_lines).strip()
                                    current_section = "raises"
                                    section_content = [stripped_line[len("Raises:"):].strip()]
                                elif current_section == "main":
                                    main_desc_lines.append(line.strip()) # Keep leading whitespace for main desc if intended
                                else:
                                    section_content.append(line.strip())

                            # Add the last collected section
                            if current_section != "main":
                                parsed_desc[current_section] = "\n".join(section_content).strip()
                            elif not parsed_desc["main"] and main_desc_lines: # Handle case where entire docstring was just main description
                                parsed_desc["main"] = "\n".join(main_desc_lines).strip()

                            # Ensure main description has content if others were parsed but main was empty
                            if not parsed_desc["main"] and (parsed_desc["args"] or parsed_desc["returns"] or parsed_desc["raises"]):
                                parsed_desc["main"] = "(No primary description provided)"

                        else:
                            parsed_desc["main"] = "No description available."
                        # --- Parse Docstring into Sections --- END

                        tool_schema = getattr(tool, 'inputSchema', {}) # Use inputSchema attribute

                        tool_details_list.append({
                            "name": tool_name,
                            "parsed_description": parsed_desc, # Store parsed sections
                            "schema": tool_schema
                        })

                print(f"Successfully retrieved details for {len(tool_details_list)} tools from {mcp_server_url}.")
                return tool_details_list # Return the list of details
    except asyncio.TimeoutError:
        print(f"MCP Check Error: Timeout during session operation with {mcp_server_url}.")
        return None
    except ConnectionRefusedError:
         print(f"MCP Check Error: Connection refused by {mcp_server_url}.")
         return None
    except Exception as e:
        print(f"MCP Check Error: Failed to get tool list from {mcp_server_url}: {type(e).__name__} - {e}")
        return None

# --- MCP Client Function to Get Tool List --- END


# --- Single Health Check Logic ---
async def perform_single_health_check(path: str) -> tuple[str, datetime | None]:
    """Performs a health check for a single service path and updates global state."""
    global SERVER_HEALTH_STATUS, SERVER_LAST_CHECK_TIME, REGISTERED_SERVERS # Ensure REGISTERED_SERVERS is global

    server_info = REGISTERED_SERVERS.get(path)
    # --- Store previous status --- START
    previous_status = SERVER_HEALTH_STATUS.get(path) # Get status before check
    # --- Store previous status --- END

    if not server_info:
        # Should not happen if called correctly, but handle defensively
        return "error: server not registered", None

    url = server_info.get("proxy_pass_url")
    is_enabled = MOCK_SERVICE_STATE.get(path, False) # Get enabled state for later check

    # --- Record check time ---
    last_checked_time = datetime.now(timezone.utc)
    SERVER_LAST_CHECK_TIME[path] = last_checked_time
    # --- Record check time ---

    if not url:
        current_status = "error: missing URL"
        SERVER_HEALTH_STATUS[path] = current_status
        print(f"Health check skipped for {path}: Missing URL.")
        # --- Regenerate Nginx if status affecting it changed --- START
        if is_enabled and previous_status == "healthy": # Was healthy, now isn't (due to missing URL)
             print(f"Status changed from healthy for {path}, regenerating Nginx config...")
             regenerate_nginx_config()
        # --- Regenerate Nginx if status affecting it changed --- END
        return current_status, last_checked_time

    # Update status to 'checking' before performing the check
    # Only print if status actually changes to 'checking'
    if previous_status != "checking":
        print(f"Setting status to 'checking' for {path} ({url})...")
        SERVER_HEALTH_STATUS[path] = "checking"
        # Optional: Consider a targeted broadcast here if immediate 'checking' feedback is desired
        # await broadcast_specific_update(path, "checking", last_checked_time)

    # --- Append /sse to the health check URL --- START
    health_check_url = url.rstrip('/') + "/sse"
    # --- Append /sse to the health check URL --- END

    # cmd = ['curl', '--head', '-s', '-f', '--max-time', str(HEALTH_CHECK_TIMEOUT_SECONDS), url]
    cmd = ['curl', '--head', '-s', '-f', '--max-time', str(HEALTH_CHECK_TIMEOUT_SECONDS), health_check_url] # Use modified URL
    current_status = "checking" # Status will be updated below

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        # Use a slightly longer timeout for wait_for to catch process hangs
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=HEALTH_CHECK_TIMEOUT_SECONDS + 2)
        stderr_str = stderr.decode().strip() if stderr else ''

        if proc.returncode == 0:
            current_status = "healthy"
            print(f"Health check successful for {path} ({url}).")

            # --- Check for transition to healthy state --- START
            # Note: Tool list fetching moved inside the status transition check
            if previous_status != "healthy":
                print(f"Service {path} transitioned to healthy. Regenerating Nginx config and fetching tool list...")
                 # --- Regenerate Nginx on transition TO healthy --- START
                regenerate_nginx_config()
                 # --- Regenerate Nginx on transition TO healthy --- END

                # Ensure url is not None before attempting connection (redundant check as url is checked above, but safe)
                if url:
                    tool_list = await get_tools_from_server(url) # Get the list of dicts

                    if tool_list is not None: # Check if list retrieval was successful
                        new_tool_count = len(tool_list)
                        # Get current list (now list of dicts)
                        current_tool_list = REGISTERED_SERVERS[path].get("tool_list", [])
                        current_tool_count = REGISTERED_SERVERS[path].get("num_tools", 0)

                        # Compare lists more carefully (simple set comparison won't work on dicts)
                        # Convert to comparable format (e.g., sorted list of JSON strings)
                        current_tool_list_str = sorted([json.dumps(t, sort_keys=True) for t in current_tool_list])
                        new_tool_list_str = sorted([json.dumps(t, sort_keys=True) for t in tool_list])

                        # if set(current_tool_list) != set(tool_list) or current_tool_count != new_tool_count:
                        if current_tool_list_str != new_tool_list_str or current_tool_count != new_tool_count:
                            print(f"Updating tool list for {path}. New count: {new_tool_count}.") # Simplified log
                            REGISTERED_SERVERS[path]["tool_list"] = tool_list # Store the new list of dicts
                            REGISTERED_SERVERS[path]["num_tools"] = new_tool_count # Update the count
                            # Save the updated server info to its file
                            if not save_server_to_file(REGISTERED_SERVERS[path]):
                                print(f"ERROR: Failed to save updated tool list/count for {path} to file.")
                        else:
                             print(f"Tool list for {path} remains unchanged. No update needed.")
                    else:
                        print(f"Failed to retrieve tool list for healthy service {path}. List/Count remains unchanged.")
                else:
                    # This case should technically not be reachable due to earlier url check
                    print(f"Cannot fetch tool list for {path}: proxy_pass_url is missing.")
            # --- Check for transition to healthy state --- END

        elif proc.returncode == 28:
            current_status = f"error: timeout ({HEALTH_CHECK_TIMEOUT_SECONDS}s)"
            print(f"Health check timeout for {path} ({url})")
        elif proc.returncode == 22: # HTTP error >= 400
            current_status = "unhealthy (HTTP error)"
            print(f"Health check unhealthy (HTTP >= 400) for {path} ({url}). Stderr: {stderr_str}")
        elif proc.returncode == 7: # Connection failed
            current_status = "error: connection failed"
            print(f"Health check connection failed for {path} ({url}). Stderr: {stderr_str}")
        else: # Other curl errors
            error_msg = f"error: check failed (code {proc.returncode})"
            if stderr_str:
                error_msg += f" - {stderr_str}"
            current_status = error_msg
            print(f"Health check failed for {path} ({url}): {error_msg}")

    except asyncio.TimeoutError:
        # This catches timeout on asyncio.wait_for, slightly different from curl's --max-time
        current_status = f"error: check process timeout"
        print(f"Health check asyncio.wait_for timeout for {path} ({url})")
    except FileNotFoundError:
        current_status = "error: command not found"
        print(f"ERROR: 'curl' command not found during health check for {path}. Cannot perform check.")
        # No need to stop all checks, just this one fails
    except Exception as e:
        current_status = f"error: {type(e).__name__}"
        print(f"ERROR: Unexpected error during health check for {path} ({url}): {e}")

    # Update the global status *after* the check completes
    SERVER_HEALTH_STATUS[path] = current_status
    print(f"Final health status for {path}: {current_status}")

    # --- Regenerate Nginx if status affecting it changed --- START
    # Check if the service is enabled AND its Nginx-relevant status changed
    if is_enabled:
        if previous_status == "healthy" and current_status != "healthy":
            print(f"Status changed FROM healthy for enabled service {path}, regenerating Nginx config...")
            regenerate_nginx_config()
        # Regeneration on transition TO healthy is handled within the proc.returncode == 0 block above
        # elif previous_status != "healthy" and current_status == "healthy":
        #     print(f"Status changed TO healthy for {path}, regenerating Nginx config...")
        #     regenerate_nginx_config() # Already handled above
    # --- Regenerate Nginx if status affecting it changed --- END


    return current_status, last_checked_time


# --- Background Health Check Task ---
async def run_health_checks():
    """Periodically checks the health of registered *enabled* services."""
    while True:
        print(f"Running periodic health checks (Interval: {HEALTH_CHECK_INTERVAL_SECONDS}s)...")
        paths_to_check = list(REGISTERED_SERVERS.keys())
        needs_broadcast = False # Flag to check if any status actually changed

        # --- Use a copy of MOCK_SERVICE_STATE for stable iteration --- START
        current_enabled_state = MOCK_SERVICE_STATE.copy()
        # --- Use a copy of MOCK_SERVICE_STATE for stable iteration --- END

        for path in paths_to_check:
            if path not in REGISTERED_SERVERS: # Check if server was removed during the loop
                continue

            # --- Use copied state for check --- START
            # is_enabled = MOCK_SERVICE_STATE.get(path, False)
            is_enabled = current_enabled_state.get(path, False)
            # --- Use copied state for check --- END
            previous_status = SERVER_HEALTH_STATUS.get(path)

            if not is_enabled:
                new_status = "disabled"
                if previous_status != new_status:
                    SERVER_HEALTH_STATUS[path] = new_status
                    # Also clear last check time when disabling? Or keep it? Keep for now.
                    # SERVER_LAST_CHECK_TIME[path] = None
                    needs_broadcast = True
                    print(f"Service {path} is disabled. Setting status.")
                continue # Skip health check for disabled services

            # --- Service is enabled, perform check using the new function ---
            print(f"Performing periodic check for enabled service: {path}")
            try:
                # Call the refactored check function
                # We only care if the status *changed* from the beginning of the cycle for broadcast purposes
                current_status, _ = await perform_single_health_check(path)
                if previous_status != current_status:
                    needs_broadcast = True
            except Exception as e:
                # Log error if the check function itself fails unexpectedly
                print(f"ERROR: Unexpected exception calling perform_single_health_check for {path}: {e}")
                # Update status to reflect this error?
                error_status = f"error: check execution failed ({type(e).__name__})"
                if previous_status != error_status:
                    SERVER_HEALTH_STATUS[path] = error_status
                    SERVER_LAST_CHECK_TIME[path] = datetime.now(timezone.utc) # Record time of failure
                    needs_broadcast = True


        print(f"Finished periodic health checks. Current status map: {SERVER_HEALTH_STATUS}")
        # Broadcast status update only if something changed during this cycle
        if needs_broadcast:
            print("Broadcasting updated health status after periodic check...")
            await broadcast_health_status()
        else:
            print("No status changes detected in periodic check, skipping broadcast.")

        # Wait for the next interval
        await asyncio.sleep(HEALTH_CHECK_INTERVAL_SECONDS)


# --- Lifespan for Startup Task ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Running startup tasks...")
    # 1. Load server definitions and persisted enabled/disabled state
    load_registered_servers_and_state()

    # 2. Perform initial health checks concurrently for *enabled* services
    print("Performing initial health checks for enabled services...")
    initial_check_tasks = []
    enabled_paths = [path for path, is_enabled in MOCK_SERVICE_STATE.items() if is_enabled]

    global SERVER_HEALTH_STATUS, SERVER_LAST_CHECK_TIME
    # Initialize status for all servers (defaults for disabled)
    for path in REGISTERED_SERVERS.keys():
        SERVER_LAST_CHECK_TIME[path] = None # Initialize last check time
        if path not in enabled_paths:
             SERVER_HEALTH_STATUS[path] = "disabled"
        else:
             # Will be set by the check task below (or remain unset if check fails badly)
             SERVER_HEALTH_STATUS[path] = "checking" # Tentative status before check runs

    print(f"Initially enabled services to check: {enabled_paths}")
    if enabled_paths:
        for path in enabled_paths:
            # Create a task for each enabled service check
            task = asyncio.create_task(perform_single_health_check(path))
            initial_check_tasks.append(task)

        # Wait for all initial checks to complete
        results = await asyncio.gather(*initial_check_tasks, return_exceptions=True)

        # Log results/errors from initial checks
        for i, result in enumerate(results):
            path = enabled_paths[i]
            if isinstance(result, Exception):
                print(f"ERROR during initial health check for {path}: {result}")
                # Status might have already been set to an error state within the check function
            else:
                status, _ = result # Unpack the result tuple
                print(f"Initial health check completed for {path}: Status = {status}")
    else:
        print("No services are initially enabled.")

    print(f"Initial health status after checks: {SERVER_HEALTH_STATUS}")

    # 3. Generate Nginx config *after* initial checks are done
    print("Generating initial Nginx configuration...")
    regenerate_nginx_config() # Generate config based on initial health status

    # 4. Start the background periodic health check task
    print("Starting background health check task...")
    health_check_task = asyncio.create_task(run_health_checks())

    # --- Yield to let the application run --- START
    yield
    # --- Yield to let the application run --- END

    # --- Shutdown tasks --- START
    print("Running shutdown tasks...")
    print("Cancelling background health check task...")
    health_check_task.cancel()
    try:
        await health_check_task
    except asyncio.CancelledError:
        print("Health check task cancelled successfully.")
    # --- Shutdown tasks --- END


app = FastAPI(lifespan=lifespan)


# --- Authentication / Session Dependency ---
def get_current_user(
    session: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> str:
    if session is None:
        raise HTTPException(
            status_code=307, detail="Not authenticated", headers={"Location": "/login"}
        )
    try:
        data = signer.loads(session, max_age=SESSION_MAX_AGE_SECONDS)
        username = data.get("username")
        if not username:
            raise HTTPException(
                status_code=307,
                detail="Invalid session data",
                headers={"Location": "/login"},
            )
        return username
    except (BadSignature, SignatureExpired):
        response = RedirectResponse(
            url="/login?error=Session+expired+or+invalid", status_code=307
        )
        response.delete_cookie(SESSION_COOKIE_NAME)
        raise HTTPException(
            status_code=307,
            detail="Session expired or invalid",
            headers={"Location": "/login"},
        )
    except Exception:
        raise HTTPException(
            status_code=307,
            detail="Authentication error",
            headers={"Location": "/login"},
        )


# --- API Authentication Dependency (returns 401 instead of redirecting) ---
def api_auth(
    session: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> str:
    if session is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        data = signer.loads(session, max_age=SESSION_MAX_AGE_SECONDS)
        username = data.get("username")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid session data")
        return username
    except (BadSignature, SignatureExpired):
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    except Exception:
        raise HTTPException(status_code=401, detail="Authentication error")


# --- Static Files and Templates (Paths relative to this script) ---
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# --- Routes ---


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, error: str | None = None):
    return templates.TemplateResponse(
        "login.html", {"request": request, "error": error}
    )


@app.post("/login")
async def login_submit(
    username: Annotated[str, Form()], password: Annotated[str, Form()]
):
    correct_username = secrets.compare_digest(
        username, os.environ.get("ADMIN_USER", "admin")
    )
    correct_password = secrets.compare_digest(
        password, os.environ.get("ADMIN_PASSWORD", "password")
    )
    if correct_username and correct_password:
        session_data = signer.dumps({"username": username})
        response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=session_data,
            max_age=SESSION_MAX_AGE_SECONDS,
            httponly=True,
            samesite="lax",
        )
        print(f"User '{username}' logged in successfully.")
        return response
    else:
        print(f"Login failed for user '{username}'.")
        return RedirectResponse(
            url="/login?error=Invalid+username+or+password",
            status_code=status.HTTP_303_SEE_OTHER,
        )


@app.post("/logout")
async def logout():
    print("User logged out.")
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


@app.get("/", response_class=HTMLResponse)
async def read_root(
    request: Request,
    username: Annotated[str, Depends(get_current_user)],
    query: str | None = None,
):
    service_data = []
    search_query = query.lower() if query else ""
    sorted_server_paths = sorted(
        REGISTERED_SERVERS.keys(), key=lambda p: REGISTERED_SERVERS[p]["server_name"]
    )
    for path in sorted_server_paths:
        server_info = REGISTERED_SERVERS[path]
        server_name = server_info["server_name"]
        # Include description and tags in search
        searchable_text = f"{server_name.lower()} {server_info.get('description', '').lower()} {' '.join(server_info.get('tags', []))}"
        if not search_query or search_query in searchable_text:
            # Pass all required fields to the template
            service_data.append(
                {
                    "display_name": server_name,
                    "path": path,
                    "description": server_info.get("description", ""),
                    "is_enabled": MOCK_SERVICE_STATE.get(path, False),
                    "tags": server_info.get("tags", []),
                    "num_tools": server_info.get("num_tools", 0),
                    "num_stars": server_info.get("num_stars", 0),
                    "is_python": server_info.get("is_python", False),
                    "license": server_info.get("license", "N/A"),
                    "health_status": SERVER_HEALTH_STATUS.get(path, "unknown"), # Get current health status
                    "last_checked_iso": SERVER_LAST_CHECK_TIME.get(path).isoformat() if SERVER_LAST_CHECK_TIME.get(path) else None
                }
            )
    # --- End Debug ---
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "services": service_data, "username": username},
    )


@app.post("/toggle/{service_path:path}")
async def toggle_service_route(
    request: Request,
    service_path: str,
    enabled: Annotated[str | None, Form()] = None,
    username: Annotated[str, Depends(get_current_user)] = None,
):
    if not service_path.startswith("/"):
        service_path = "/" + service_path
    if service_path not in REGISTERED_SERVERS:
        raise HTTPException(status_code=404, detail="Service path not registered")

    new_state = enabled == "on"
    MOCK_SERVICE_STATE[service_path] = new_state
    server_name = REGISTERED_SERVERS[service_path]["server_name"]
    print(
        f"Simulated toggle for '{server_name}' ({service_path}) to {new_state} by user '{username}'"
    )

    # --- Update health status immediately on toggle --- START
    new_status = ""
    last_checked_iso = None
    last_checked_dt = None # Initialize datetime object

    if new_state:
        # Perform immediate check when enabling
        print(f"Performing immediate health check for {service_path} upon toggle ON...")
        try:
            new_status, last_checked_dt = await perform_single_health_check(service_path)
            last_checked_iso = last_checked_dt.isoformat() if last_checked_dt else None
            print(f"Immediate check for {service_path} completed. Status: {new_status}")
        except Exception as e:
            # Handle potential errors during the immediate check itself
            print(f"ERROR during immediate health check for {service_path}: {e}")
            new_status = f"error: immediate check failed ({type(e).__name__})"
            # Update global state to reflect this error
            SERVER_HEALTH_STATUS[service_path] = new_status
            last_checked_dt = SERVER_LAST_CHECK_TIME.get(service_path) # Use time if check started
            last_checked_iso = last_checked_dt.isoformat() if last_checked_dt else None
    else:
        # When disabling, set status to disabled and keep last check time
        new_status = "disabled"
        # Keep the last check time from when it was enabled
        last_checked_dt = SERVER_LAST_CHECK_TIME.get(service_path)
        last_checked_iso = last_checked_dt.isoformat() if last_checked_dt else None
        # Update global state directly when disabling
        SERVER_HEALTH_STATUS[service_path] = new_status
        print(f"Service {service_path} toggled OFF. Status set to disabled.")

    # --- Send *targeted* update via WebSocket --- START
    # Send immediate feedback for the toggled service only
    # Always get the latest num_tools from the registry
    current_num_tools = REGISTERED_SERVERS.get(service_path, {}).get("num_tools", 0)

    update_data = {
        service_path: {
            "status": new_status,
            "last_checked_iso": last_checked_iso,
            "num_tools": current_num_tools # Include num_tools
        }
    }
    message = json.dumps(update_data)
    print(f"--- TOGGLE: Sending targeted update: {message}")

    # Create task to send without blocking the request
    async def send_specific_update():
        disconnected_clients = set()
        current_connections = list(active_connections)
        send_tasks = []
        for conn in current_connections:
            send_tasks.append((conn, conn.send_text(message)))

        results = await asyncio.gather(*(task for _, task in send_tasks), return_exceptions=True)

        for i, result in enumerate(results):
            conn, _ = send_tasks[i]
            if isinstance(result, Exception):
                print(f"Error sending toggle update to WebSocket client {conn.client}: {result}. Marking for removal.")
                disconnected_clients.add(conn)
        if disconnected_clients:
            print(f"Removing {len(disconnected_clients)} disconnected clients after toggle update.")
            for conn in disconnected_clients:
                if conn in active_connections:
                    active_connections.remove(conn)

    asyncio.create_task(send_specific_update())
    # --- Send *targeted* update via WebSocket --- END

    # --- Persist the updated state --- START
    try:
        with open(STATE_FILE_PATH, "w") as f:
            json.dump(MOCK_SERVICE_STATE, f, indent=2)
        print(f"Persisted state to {STATE_FILE_PATH}")
    except Exception as e:
        print(f"ERROR: Failed to persist state to {STATE_FILE_PATH}: {e}")
        # Decide if we should raise an error or just log
    # --- Persist the updated state --- END

    # Regenerate Nginx config after toggling state
    if not regenerate_nginx_config():
        print("ERROR: Failed to update Nginx configuration after toggle.")

    # --- Return JSON instead of Redirect --- START
    final_status = SERVER_HEALTH_STATUS.get(service_path, "unknown")
    final_last_checked_dt = SERVER_LAST_CHECK_TIME.get(service_path)
    final_last_checked_iso = final_last_checked_dt.isoformat() if final_last_checked_dt else None
    final_num_tools = REGISTERED_SERVERS.get(service_path, {}).get("num_tools", 0)

    return JSONResponse(
        status_code=200,
        content={
            "message": f"Toggle request for {service_path} processed.",
            "service_path": service_path,
            "new_enabled_state": new_state, # The state it was set to
            "status": final_status, # The status after potential immediate check
            "last_checked_iso": final_last_checked_iso,
            "num_tools": final_num_tools
        }
    )
    # --- Return JSON instead of Redirect --- END

    # query_param = request.query_params.get("query", "")
    # redirect_url = f"/?query={query_param}" if query_param else "/"
    # return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@app.post("/register")
async def register_service(
    name: Annotated[str, Form()],
    description: Annotated[str, Form()],
    path: Annotated[str, Form()],
    proxy_pass_url: Annotated[str, Form()],
    tags: Annotated[str, Form()] = "",
    num_tools: Annotated[int, Form()] = 0,
    num_stars: Annotated[int, Form()] = 0,
    is_python: Annotated[bool, Form()] = False,
    license_str: Annotated[str, Form(alias="license")] = "N/A",
    username: Annotated[str, Depends(api_auth)] = None,
):
    print(f"[DEBUG] register_service() called with parameters:")
    print(f"[DEBUG] - name: {name}")
    print(f"[DEBUG] - description: {description}")
    print(f"[DEBUG] - path: {path}")
    print(f"[DEBUG] - proxy_pass_url: {proxy_pass_url}")
    print(f"[DEBUG] - tags: {tags}")
    print(f"[DEBUG] - num_tools: {num_tools}")
    print(f"[DEBUG] - num_stars: {num_stars}")
    print(f"[DEBUG] - is_python: {is_python}")
    print(f"[DEBUG] - license_str: {license_str}")
    print(f"[DEBUG] - username: {username}")

    # Ensure path starts with a slash
    if not path.startswith("/"):
        path = "/" + path
        print(f"[DEBUG] Path adjusted to start with slash: {path}")

    # Check if path already exists
    if path in REGISTERED_SERVERS:
        print(f"[ERROR] Service registration failed: path '{path}' already exists")
        return JSONResponse(
            status_code=400,
            content={"error": f"Service with path '{path}' already exists"},
        )

    # Process tags: split string, strip whitespace, filter empty
    tag_list = [tag.strip() for tag in tags.split(",") if tag.strip()]
    print(f"[DEBUG] Processed tags: {tag_list}")

    # Create new server entry with all fields
    server_entry = {
        "server_name": name,
        "description": description,
        "path": path,
        "proxy_pass_url": proxy_pass_url,
        "tags": tag_list,
        "num_tools": num_tools,
        "num_stars": num_stars,
        "is_python": is_python,
        "license": license_str,
        "tool_list": [] # Initialize tool list
    }
    print(f"[DEBUG] Created server entry: {json.dumps(server_entry, indent=2)}")

    # Save to individual file
    print(f"[DEBUG] Attempting to save server data to file...")
    success = save_server_to_file(server_entry)
    if not success:
        print(f"[ERROR] Failed to save server data to file")
        return JSONResponse(
            status_code=500, content={"error": "Failed to save server data"}
        )
    print(f"[DEBUG] Successfully saved server data to file")

    # Add to in-memory registry and default to disabled
    print(f"[DEBUG] Adding server to in-memory registry...")
    REGISTERED_SERVERS[path] = server_entry
    print(f"[DEBUG] Setting initial service state to disabled")
    MOCK_SERVICE_STATE[path] = False
    # Set initial health status for the new service (always start disabled)
    print(f"[DEBUG] Setting initial health status to 'disabled'")
    SERVER_HEALTH_STATUS[path] = "disabled" # Start disabled
    SERVER_LAST_CHECK_TIME[path] = None # No check time yet
    # Ensure num_tools is present in the in-memory dict immediately
    if "num_tools" not in REGISTERED_SERVERS[path]:
        print(f"[DEBUG] Adding missing num_tools field to in-memory registry")
        REGISTERED_SERVERS[path]["num_tools"] = 0

    # Regenerate Nginx config after successful registration
    print(f"[DEBUG] Attempting to regenerate Nginx configuration...")
    if not regenerate_nginx_config():
        print(f"[ERROR] Failed to update Nginx configuration after registration")
    else:
        print(f"[DEBUG] Successfully regenerated Nginx configuration")

    print(f"[INFO] New service registered: '{name}' at path '{path}' by user '{username}'")

    # --- Persist the updated state after registration --- START
    try:
        print(f"[DEBUG] Attempting to persist state to {STATE_FILE_PATH}...")
        with open(STATE_FILE_PATH, "w") as f:
            json.dump(MOCK_SERVICE_STATE, f, indent=2)
        print(f"[DEBUG] Successfully persisted state to {STATE_FILE_PATH}")
    except Exception as e:
        print(f"[ERROR] Failed to persist state to {STATE_FILE_PATH}: {str(e)}")
    # --- Persist the updated state after registration --- END

    # Broadcast the updated status after registration
    print(f"[DEBUG] Creating task to broadcast health status...")
    asyncio.create_task(broadcast_health_status())

    print(f"[DEBUG] Registration complete, returning success response")
    return JSONResponse(
        status_code=201,
        content={
            "message": "Service registered successfully",
            "service": server_entry,
        },
    )

@app.get("/api/server_details/{service_path:path}")
async def get_server_details(
    service_path: str,
    username: Annotated[str, Depends(api_auth)]
):
    # Normalize the path to ensure it starts with '/'
    if not service_path.startswith('/'):
        service_path = '/' + service_path
    
    # Special case: if path is 'all' or '/all', return details for all servers
    if service_path == '/all':
        # Return a dictionary of all registered servers
        return REGISTERED_SERVERS
    
    # Regular case: return details for a specific server
    server_info = REGISTERED_SERVERS.get(service_path)
    if not server_info:
        raise HTTPException(status_code=404, detail="Service path not registered")
    
    # Return the full server info, including proxy_pass_url
    return server_info


# --- Endpoint to get tool list for a service --- START
@app.get("/api/tools/{service_path:path}")
async def get_service_tools(
    service_path: str,
    username: Annotated[str, Depends(api_auth)] # Requires authentication
):
    if not service_path.startswith('/'):
        service_path = '/' + service_path

    # Handle special case for '/all' to return tools from all servers
    if service_path == '/all':
        all_tools = []
        all_servers_tools = {}
        
        for path, server_info in REGISTERED_SERVERS.items():
            tool_list = server_info.get("tool_list")
            
            if tool_list is not None and isinstance(tool_list, list):
                # Add server information to each tool
                server_tools = []
                for tool in tool_list:
                    # Create a copy of the tool with server info added
                    tool_with_server = dict(tool)
                    tool_with_server["server_path"] = path
                    tool_with_server["server_name"] = server_info.get("server_name", "Unknown")
                    server_tools.append(tool_with_server)
                
                all_tools.extend(server_tools)
                all_servers_tools[path] = server_tools
        
        return {
            "service_path": "all",
            "tools": all_tools,
            "servers": all_servers_tools
        }
    
    # Handle specific server case (existing logic)
    server_info = REGISTERED_SERVERS.get(service_path)
    if not server_info:
        raise HTTPException(status_code=404, detail="Service path not registered")

    tool_list = server_info.get("tool_list") # Get the stored list

    if tool_list is None:
        # This might happen if the service hasn't become healthy yet
        raise HTTPException(status_code=404, detail="Tool list not available yet. Service may not be healthy or check is pending.")
    elif not isinstance(tool_list, list):
         # Data integrity check
        print(f"Warning: tool_list for {service_path} is not a list: {type(tool_list)}")
        raise HTTPException(status_code=500, detail="Internal server error: Invalid tool list format.")

    return {"service_path": service_path, "tools": tool_list}
# --- Endpoint to get tool list for a service --- END


# --- Refresh Endpoint --- START
@app.post("/api/refresh/{service_path:path}")
async def refresh_service(service_path: str, username: Annotated[str, Depends(api_auth)]):
    if not service_path.startswith('/'):
        service_path = '/' + service_path

    # Check if service exists
    if service_path not in REGISTERED_SERVERS:
        raise HTTPException(status_code=404, detail="Service path not registered")

    # Check if service is enabled
    is_enabled = MOCK_SERVICE_STATE.get(service_path, False)
    if not is_enabled:
        raise HTTPException(status_code=400, detail="Cannot refresh a disabled service")

    print(f"Manual refresh requested for {service_path} by user '{username}'...")
    try:
        # Trigger the health check (which also updates tools if healthy)
        await perform_single_health_check(service_path)
        # --- Regenerate Nginx config after manual refresh --- START
        # The health check itself might trigger regeneration, but do it explicitly
        # here too to ensure it happens after the refresh attempt completes.
        print(f"Regenerating Nginx config after manual refresh for {service_path}...")
        regenerate_nginx_config()
        # --- Regenerate Nginx config after manual refresh --- END
    except Exception as e:
        # Catch potential errors during the check itself
        print(f"ERROR during manual refresh check for {service_path}: {e}")
        # Update status to reflect the error
        error_status = f"error: refresh execution failed ({type(e).__name__})"
        SERVER_HEALTH_STATUS[service_path] = error_status
        SERVER_LAST_CHECK_TIME[service_path] = datetime.now(timezone.utc)
        # Still broadcast the error state
        await broadcast_single_service_update(service_path)
        # --- Regenerate Nginx config even after refresh failure --- START
        # Ensure Nginx reflects the error state if it was previously healthy
        print(f"Regenerating Nginx config after manual refresh failed for {service_path}...")
        regenerate_nginx_config()
        # --- Regenerate Nginx config even after refresh failure --- END
        # Return error response
        raise HTTPException(status_code=500, detail=f"Refresh check failed: {e}")

    # Check completed, broadcast the latest status
    await broadcast_single_service_update(service_path)

    # Return the latest status from global state
    final_status = SERVER_HEALTH_STATUS.get(service_path, "unknown")
    final_last_checked_dt = SERVER_LAST_CHECK_TIME.get(service_path)
    final_last_checked_iso = final_last_checked_dt.isoformat() if final_last_checked_dt else None
    final_num_tools = REGISTERED_SERVERS.get(service_path, {}).get("num_tools", 0)

    return {
        "service_path": service_path,
        "status": final_status,
        "last_checked_iso": final_last_checked_iso,
        "num_tools": final_num_tools
    }
# --- Refresh Endpoint --- END


# --- Add Edit Routes ---

@app.get("/edit/{service_path:path}", response_class=HTMLResponse)
async def edit_server_form(
    request: Request, 
    service_path: str, 
    username: Annotated[str, Depends(get_current_user)] # Require login
):
    if not service_path.startswith('/'):
        service_path = '/' + service_path

    server_info = REGISTERED_SERVERS.get(service_path)
    if not server_info:
        raise HTTPException(status_code=404, detail="Service path not found")
    
    return templates.TemplateResponse(
        "edit_server.html", 
        {"request": request, "server": server_info, "username": username}
    )

@app.post("/edit/{service_path:path}")
async def edit_server_submit(
    service_path: str, 
    # Required Form fields
    name: Annotated[str, Form()], 
    proxy_pass_url: Annotated[str, Form()], 
    # Dependency
    username: Annotated[str, Depends(get_current_user)], 
    # Optional Form fields
    description: Annotated[str, Form()] = "", 
    tags: Annotated[str, Form()] = "", 
    num_tools: Annotated[int, Form()] = 0, 
    num_stars: Annotated[int, Form()] = 0, 
    is_python: Annotated[bool | None, Form()] = False,  
    license_str: Annotated[str, Form(alias="license")] = "N/A", 
):
    if not service_path.startswith('/'):
        service_path = '/' + service_path

    # Check if the server exists
    if service_path not in REGISTERED_SERVERS:
        raise HTTPException(status_code=404, detail="Service path not found")

    # Process tags
    tag_list = [tag.strip() for tag in tags.split(',') if tag.strip()]

    # Prepare updated server data (keeping original path)
    updated_server_entry = {
        "server_name": name,
        "description": description,
        "path": service_path, # Keep original path
        "proxy_pass_url": proxy_pass_url,
        "tags": tag_list,
        "num_tools": num_tools,
        "num_stars": num_stars,
        "is_python": bool(is_python), # Convert checkbox value
        "license": license_str,
    }

    # Save updated data to file
    success = save_server_to_file(updated_server_entry)
    if not success:
        # Optionally render form again with an error message
        raise HTTPException(status_code=500, detail="Failed to save updated server data")

    # Update in-memory registry
    REGISTERED_SERVERS[service_path] = updated_server_entry

    # Regenerate Nginx config as proxy_pass_url might have changed
    if not regenerate_nginx_config():
        print("ERROR: Failed to update Nginx configuration after edit.")
        # Consider how to notify user - maybe flash message system needed

    print(f"Server '{name}' ({service_path}) updated by user '{username}'")

    # Redirect back to the main page
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


# --- Helper function to broadcast single service update --- START
async def broadcast_single_service_update(service_path: str):
    """Sends the current status, tool count, and last check time for a specific service."""
    global active_connections, SERVER_HEALTH_STATUS, SERVER_LAST_CHECK_TIME, REGISTERED_SERVERS

    if not active_connections:
        return # No clients connected

    status = SERVER_HEALTH_STATUS.get(service_path, "unknown")
    last_checked_dt = SERVER_LAST_CHECK_TIME.get(service_path)
    last_checked_iso = last_checked_dt.isoformat() if last_checked_dt else None
    num_tools = REGISTERED_SERVERS.get(service_path, {}).get("num_tools", 0)

    update_data = {
        service_path: {
            "status": status,
            "last_checked_iso": last_checked_iso,
            "num_tools": num_tools
        }
    }
    message = json.dumps(update_data)
    print(f"--- BROADCAST SINGLE: Sending update for {service_path}: {message}")

    # Use the same concurrent sending logic as in toggle
    disconnected_clients = set()
    current_connections = list(active_connections) # Copy to iterate safely
    send_tasks = []
    for conn in current_connections:
        send_tasks.append((conn, conn.send_text(message)))

    results = await asyncio.gather(*(task for _, task in send_tasks), return_exceptions=True)

    for i, result in enumerate(results):
        conn, _ = send_tasks[i]
        if isinstance(result, Exception):
            print(f"Error sending single update to WebSocket client {conn.client}: {result}. Marking for removal.")
            disconnected_clients.add(conn)
    if disconnected_clients:
        print(f"Removing {len(disconnected_clients)} disconnected clients after single update broadcast.")
        for conn in disconnected_clients:
            if conn in active_connections:
                active_connections.remove(conn)
# --- Helper function to broadcast single service update --- END


# --- WebSocket Endpoint ---
@app.websocket("/ws/health_status")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.add(websocket)
    print(f"WebSocket client connected: {websocket.client}")
    try:
        # --- Send initial status upon connection (Formatted) --- START
        initial_data_to_send = {}
        for path, status in SERVER_HEALTH_STATUS.items():
            last_checked_dt = SERVER_LAST_CHECK_TIME.get(path)
            # Send ISO string or None
            last_checked_iso = last_checked_dt.isoformat() if last_checked_dt else None
            # Get the current tool count from REGISTERED_SERVERS
            num_tools = REGISTERED_SERVERS.get(path, {}).get("num_tools", 0) # Default to 0 if not found

            initial_data_to_send[path] = {
                "status": status,
                "last_checked_iso": last_checked_iso,
                "num_tools": num_tools # --- Add num_tools --- START
            }
            # --- Add num_tools --- END
        await websocket.send_text(json.dumps(initial_data_to_send))
        # --- Send initial status upon connection (Formatted) --- END

        # Keep connection open, handle potential disconnects
        while True:
            # We don't expect messages from client in this case, just keep alive
            await websocket.receive_text() # This will raise WebSocketDisconnect if client closes
    except WebSocketDisconnect:
        print(f"WebSocket client disconnected: {websocket.client}")
    except Exception as e:
        print(f"WebSocket error for {websocket.client}: {e}")
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)
            print(f"WebSocket connection removed: {websocket.client}")


# --- Run (for local testing) ---
# Use: uvicorn registry.main:app --reload --host 0.0.0.0 --port 7860 --root-path /home/ubuntu/mcp-gateway
# (Running from parent dir)

# If running directly (python registry/main.py):
# if __name__ == "__main__":
#     import uvicorn
#     # Running this way makes relative paths tricky, better to use uvicorn command from parent
#     uvicorn.run(app, host="0.0.0.0", port=7860)
