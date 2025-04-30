import os
import re
import json
import secrets
from contextlib import asynccontextmanager
from pathlib import Path  # Import Path
from typing import Annotated

from fastapi import FastAPI, Request, Depends, HTTPException, Form, status, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from dotenv import load_dotenv

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

# In-memory state store
REGISTERED_SERVERS = {}
MOCK_SERVICE_STATE = {}

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

            if not proxy_url:
                print(f"Warning: Skipping server '{server_info['server_name']}' ({path}) - missing proxy_pass_url.")
                continue

            if is_enabled:
                block = LOCATION_BLOCK_TEMPLATE.format(
                    path=path,
                    proxy_pass_url=proxy_url
                )
            else:
                block = COMMENTED_LOCATION_BLOCK_TEMPLATE.format(
                    path=path,
                    proxy_pass_url=proxy_url
                )
            location_blocks.append(block)

        final_config = template_content.replace("# {{LOCATION_BLOCKS}}", "\n".join(location_blocks))

        with open(NGINX_CONFIG_PATH, 'w') as f_out:
            f_out.write(final_config)
        print("Nginx config regeneration successful.")
        return True

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

    # Initialize mock state (Default to disabled unless state is restored elsewhere)
    # We no longer read Nginx config to get the initial state.
    # State should ideally be persisted or default to disabled on startup.
    print("Initializing mock service state (defaulting to disabled)...")
    MOCK_SERVICE_STATE = {path: False for path in REGISTERED_SERVERS.keys()}
    # TODO: Consider loading initial state from a persistent store if needed
    print(f"Initial mock state: {MOCK_SERVICE_STATE}")


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


# --- Lifespan for Startup Task ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Running startup tasks...")
    load_registered_servers_and_state()
    regenerate_nginx_config() # Generate config after loading state
    yield
    print("Running shutdown tasks...")


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

    # Regenerate Nginx config after toggling state
    if not regenerate_nginx_config():
        # Handle error - maybe return an error response or just log it
        print("ERROR: Failed to update Nginx configuration after toggle.")
        # Consider raising an HTTPException or returning a specific error response

    query_param = request.query_params.get("query", "")
    redirect_url = f"/?query={query_param}" if query_param else "/"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


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
    # Ensure path starts with a slash
    if not path.startswith("/"):
        path = "/" + path

    # Check if path already exists
    if path in REGISTERED_SERVERS:
        return JSONResponse(
            status_code=400,
            content={"error": f"Service with path '{path}' already exists"},
        )

    # Process tags: split string, strip whitespace, filter empty
    tag_list = [tag.strip() for tag in tags.split(",") if tag.strip()]

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
    }

    # Save to individual file
    success = save_server_to_file(server_entry)
    if not success:
        return JSONResponse(
            status_code=500, content={"error": "Failed to save server data"}
        )

    # Add to in-memory registry and default to disabled
    REGISTERED_SERVERS[path] = server_entry
    MOCK_SERVICE_STATE[path] = False

    # Regenerate Nginx config after successful registration
    if not regenerate_nginx_config():
        # Handle error - registration succeeded but config generation failed.
        # Maybe log the error but still return success for registration?
        print("ERROR: Failed to update Nginx configuration after registration.")
        # Consider adding a warning to the response

    print(f"New service registered: '{name}' at path '{path}' by user '{username}'")

    return JSONResponse(
        status_code=201,
        content={
            "message": "Service registered successfully",
            "service": server_entry,
            # Optional: Add a warning if config generation failed
            # "warning": "Nginx configuration update failed, please check logs."
        },
    )


@app.get("/api/server_details/{service_path:path}")
async def get_server_details(
    service_path: str,
    username: Annotated[str, Depends(api_auth)]
):
    if not service_path.startswith('/'):
        service_path = '/' + service_path
    
    server_info = REGISTERED_SERVERS.get(service_path)
    if not server_info:
        raise HTTPException(status_code=404, detail="Service path not registered")
    
    # Return the full server info, including proxy_pass_url
    return server_info


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


# --- Run (for local testing) ---
# Use: uvicorn registry.main:app --reload --host 0.0.0.0 --port 7860 --root-path /home/ubuntu/mcp-gateway
# (Running from parent dir)

# If running directly (python registry/main.py):
# if __name__ == "__main__":
#     import uvicorn
#     # Running this way makes relative paths tricky, better to use uvicorn command from parent
#     uvicorn.run(app, host="0.0.0.0", port=7860)
