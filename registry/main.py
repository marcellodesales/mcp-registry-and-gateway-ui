import os
import re
import json
import secrets
from contextlib import asynccontextmanager
from pathlib import Path # Import Path
from typing import Annotated

from fastapi import FastAPI, Request, Depends, HTTPException, Form, status, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from starlette.responses import Response
from dotenv import load_dotenv

# Determine the base directory of this script (registry folder)
BASE_DIR = Path(__file__).resolve().parent

load_dotenv(dotenv_path=BASE_DIR.parent / ".env") # Load .env from parent directory

# --- Configuration & State (Paths relative to this script) ---
NGINX_CONFIG_PATH = BASE_DIR / "nginx_mcp_revproxy.conf" # In the same folder as main.py
SERVERS_METADATA_PATH = BASE_DIR / "servers" / "servers.json" # In servers subfolder
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

# In-memory state store
REGISTERED_SERVERS = {}
MOCK_SERVICE_STATE = {}

# Session management configuration
SECRET_KEY = os.environ.get("SECRET_KEY", "insecure-default-key-for-testing-only")
if SECRET_KEY == "insecure-default-key-for-testing-only":
    print("\nWARNING: Using insecure default SECRET_KEY. Set a strong SECRET_KEY environment variable for production.\n")
SESSION_COOKIE_NAME = "mcp_gateway_session"
signer = URLSafeTimedSerializer(SECRET_KEY)
SESSION_MAX_AGE_SECONDS = 60 * 60 * 8 # 8 hours

# --- Helper Functions for Reading Config/State (Adapted) ---

def get_nginx_config_content():
    try:
        with open(NGINX_CONFIG_PATH, 'r') as f: return f.readlines()
    except Exception as e:
        print(f"Warning: Could not read Nginx config {NGINX_CONFIG_PATH} for initial state: {e}")
        return None

def find_location_block(lines, service_path):
    start_line, end_line, brace_count, in_block = -1, -1, 0, False
    pattern = re.compile(r"^\s*(#?\s*location\s+" + re.escape(service_path) + r"\s*\{)")
    if not lines: return -1, -1
    for i, line in enumerate(lines):
        if start_line == -1:
            match = pattern.match(line)
            if match:
                start_line, in_block = i, True
                brace_count += line.count('{') - line.count('}')
                if brace_count == 0: end_line = i; break
        elif in_block:
            brace_count += line.count('{') - line.count('}')
            if brace_count <= 0: end_line = i; break
    return start_line, end_line

def get_initial_enabled_state_from_nginx(service_path, nginx_lines):
    if not nginx_lines: return False
    start_line, _ = find_location_block(nginx_lines, service_path)
    if start_line == -1: return False
    return not nginx_lines[start_line].strip().startswith("#")

# --- Data Loading ---
def load_registered_servers_and_state():
    global REGISTERED_SERVERS, MOCK_SERVICE_STATE
    print(f"Loading server definitions from {SERVERS_METADATA_PATH}...")
    temp_servers = {}
    try:
        with open(SERVERS_METADATA_PATH, 'r') as f:
            servers_list = json.load(f)
            if not isinstance(servers_list, list):
                 raise ValueError("servers.json should contain a JSON list.")
            for server_info in servers_list:
                if isinstance(server_info, dict) and "path" in server_info and "Server Name" in server_info:
                    server_path = server_info["path"]
                    if server_path in temp_servers:
                         print(f"Warning: Duplicate server path found in {SERVERS_METADATA_PATH}: {server_path}. Skipping duplicate.")
                         continue
                    server_info["description"] = server_info.get("description", "")
                    temp_servers[server_path] = server_info
                else:
                    print(f"Warning: Invalid server entry format found in {SERVERS_METADATA_PATH}. Skipping: {server_info}")
            REGISTERED_SERVERS = temp_servers
            print(f"Successfully loaded {len(REGISTERED_SERVERS)} servers.")
    except FileNotFoundError:
        print(f"ERROR: Server definition file not found at {SERVERS_METADATA_PATH}. No servers loaded.")
        REGISTERED_SERVERS = {}
    except json.JSONDecodeError as e:
        print(f"ERROR: Could not parse JSON from {SERVERS_METADATA_PATH}: {e}. No servers loaded.")
        REGISTERED_SERVERS = {}
    except Exception as e:
        print(f"ERROR: An unexpected error occurred loading {SERVERS_METADATA_PATH}: {e}. No servers loaded.")
        REGISTERED_SERVERS = {}

    # Refresh mock state based on loaded servers and current Nginx config state
    print("Initializing/refreshing mock service state based on Nginx config...")
    MOCK_SERVICE_STATE = {}
    nginx_lines = get_nginx_config_content()
    for path in REGISTERED_SERVERS.keys():
        MOCK_SERVICE_STATE[path] = get_initial_enabled_state_from_nginx(path, nginx_lines)
    print(f"Initial mock state: {MOCK_SERVICE_STATE}")

# --- Lifespan for Startup Task ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Running startup tasks...")
    load_registered_servers_and_state()
    yield
    print("Running shutdown tasks...")

app = FastAPI(lifespan=lifespan)

# --- Authentication / Session Dependency ---
def get_current_user(session: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None) -> str:
    if session is None:
        raise HTTPException(status_code=307, detail="Not authenticated", headers={"Location": "/login"})
    try:
        data = signer.loads(session, max_age=SESSION_MAX_AGE_SECONDS)
        username = data.get("username")
        if not username:
             raise HTTPException(status_code=307, detail="Invalid session data", headers={"Location": "/login"})
        return username
    except (BadSignature, SignatureExpired):
        response = RedirectResponse(url="/login?error=Session+expired+or+invalid", status_code=307)
        response.delete_cookie(SESSION_COOKIE_NAME)
        raise HTTPException(status_code=307, detail="Session expired or invalid", headers={"Location": "/login"})
    except Exception:
        raise HTTPException(status_code=307, detail="Authentication error", headers={"Location": "/login"})

# --- Static Files and Templates (Paths relative to this script) ---
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# --- Routes ---

@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, error: str | None = None):
    return templates.TemplateResponse("login.html", {"request": request, "error": error})

@app.post("/login")
async def login_submit(username: Annotated[str, Form()], password: Annotated[str, Form()]):
    correct_username = secrets.compare_digest(username, os.environ.get("ADMIN_USER", "admin"))
    correct_password = secrets.compare_digest(password, os.environ.get("ADMIN_PASSWORD", "password"))
    if correct_username and correct_password:
        session_data = signer.dumps({"username": username})
        response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(key=SESSION_COOKIE_NAME, value=session_data, max_age=SESSION_MAX_AGE_SECONDS, httponly=True, samesite="lax")
        print(f"User '{username}' logged in successfully.")
        return response
    else:
        print(f"Login failed for user '{username}'.")
        return RedirectResponse(url="/login?error=Invalid+username+or+password", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/logout")
async def logout():
    print("User logged out.")
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, username: Annotated[str, Depends(get_current_user)], query: str | None = None):
    service_data = []
    search_query = query.lower() if query else ""
    sorted_server_paths = sorted(REGISTERED_SERVERS.keys(), key=lambda p: REGISTERED_SERVERS[p]["Server Name"])
    for path in sorted_server_paths:
        server_info = REGISTERED_SERVERS[path]
        server_name = server_info["Server Name"]
        if not search_query or search_query in server_name.lower() or search_query in server_info["description"].lower():
            service_data.append({
                "display_name": server_name,
                "path": path,
                "description": server_info["description"],
                "is_enabled": MOCK_SERVICE_STATE.get(path, False)
            })
    # --- DEBUG: Print data being sent to template ---
    print("\n--- Data for Template ---")
    print(service_data)
    print("-------------------------\n")
    # --- End Debug ---
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "services": service_data, "username": username}
    )

@app.post("/toggle/{service_path:path}")
async def toggle_service_route(
    request: Request,
    service_path: str,
    enabled: Annotated[str | None, Form()] = None,
    username: Annotated[str, Depends(get_current_user)] = None
):
    if not service_path.startswith('/'):
        service_path = '/' + service_path
    if service_path not in REGISTERED_SERVERS:
        raise HTTPException(status_code=404, detail="Service path not registered")
    new_state = (enabled == "on")
    MOCK_SERVICE_STATE[service_path] = new_state
    server_name = REGISTERED_SERVERS[service_path]["Server Name"]
    print(f"Simulated toggle for '{server_name}' ({service_path}) to {new_state} by user '{username}'")
    query_param = request.query_params.get('query', '')
    redirect_url = f"/?query={query_param}" if query_param else "/"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)

@app.post("/rescan")
async def rescan_services_route(
    request: Request,
    username: Annotated[str, Depends(get_current_user)] = None
):
    print(f"Rescan triggered by user '{username}'...")
    load_registered_servers_and_state()
    query_param = request.query_params.get('query', '')
    redirect_url = f"/?query={query_param}" if query_param else "/"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)

# --- Run (for local testing) ---
# Use: uvicorn registry.main:app --reload --host 0.0.0.0 --port 7860 --root-path /home/ubuntu/mcp-gateway
# (Running from parent dir)

# If running directly (python registry/main.py):
# if __name__ == "__main__":
#     import uvicorn
#     # Running this way makes relative paths tricky, better to use uvicorn command from parent
#     uvicorn.run(app, host="0.0.0.0", port=7860) 