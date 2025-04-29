import os
import re
import json
import secrets
import base64
import binascii
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, Request, Depends, HTTPException, Form, status, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from starlette.responses import Response
from dotenv import load_dotenv

load_dotenv()

# --- Configuration & State ---
NGINX_CONFIG_PATH = "nginx_mcp_revproxy.conf"
SERVICES_JSON_PATH = "services.json"

LOADED_SERVICES = {}
MOCK_SERVICE_STATE = {}

# Session management configuration
# IMPORTANT: Set a strong, secret key in your environment (.env file or system env)
# Example: SECRET_KEY=your-very-strong-random-secret-key
SECRET_KEY = os.environ.get("SECRET_KEY", "insecure-default-key-for-testing-only")
if SECRET_KEY == "insecure-default-key-for-testing-only":
    print("\nWARNING: Using insecure default SECRET_KEY. Set a strong SECRET_KEY environment variable for production.\n")
SESSION_COOKIE_NAME = "mcp_gateway_session"
signer = URLSafeTimedSerializer(SECRET_KEY)
SESSION_MAX_AGE_SECONDS = 60 * 60 * 8 # 8 hours, for example

# --- Service Discovery / State Management (Adapted from admin_ui.py) ---

def generate_display_name(path):
    if not path or path == '/': return "Root"
    name = path.strip('/').replace('-', ' ').replace('_', ' ')
    return name.title()

def get_config_content(): # Reads the TEST config file
    try:
        with open(NGINX_CONFIG_PATH, 'r') as f: return f.readlines()
    except Exception as e:
        print(f"Error reading TEST config file {NGINX_CONFIG_PATH}: {e}")
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

def get_initial_state_from_config(service_display_name):
    service_path = LOADED_SERVICES.get(service_display_name)
    if not service_path: return False
    lines = get_config_content()
    if not lines: return False
    start_line, _ = find_location_block(lines, service_path)
    if start_line == -1: return False
    return not lines[start_line].strip().startswith("#")

def discover_services_from_nginx():
    lines = get_config_content()
    if not lines: return {}
    services = {}
    pattern = re.compile(r"^\s*(#?\s*location)\s+([/\w_-]+)\s*\{")
    for line in lines:
         match = pattern.match(line)
         if match:
            service_path = match.group(2)
            if service_path != '/':
                display_name = generate_display_name(service_path)
                original_display_name, suffix = display_name, 1
                while display_name in services:
                    suffix += 1
                    display_name = f"{original_display_name}_{suffix}"
                services[display_name] = service_path
    print(f"Discovered services in test file: {services}")
    return services

def save_services_to_json(services_dict):
    try:
        with open(SERVICES_JSON_PATH, 'w') as f: json.dump(services_dict, f, indent=4)
        print(f"Services saved to {SERVICES_JSON_PATH}")
    except Exception as e:
        print(f"Error saving services to {SERVICES_JSON_PATH}: {e}")

def load_services_and_state():
    global LOADED_SERVICES, MOCK_SERVICE_STATE
    loaded_ok = False
    if os.path.exists(SERVICES_JSON_PATH):
        try:
            with open(SERVICES_JSON_PATH, 'r') as f: LOADED_SERVICES = json.load(f)
            print(f"Services loaded from {SERVICES_JSON_PATH}")
            loaded_ok = True
        except Exception as e:
            print(f"Error loading/parsing {SERVICES_JSON_PATH}: {e}")

    if not loaded_ok:
        print("Running initial discovery...")
        LOADED_SERVICES = discover_services_from_nginx()
        save_services_to_json(LOADED_SERVICES)

    print("Initializing/refreshing mock service state...")
    MOCK_SERVICE_STATE = {}
    if get_config_content(): # Ensure we can read the config for initial state
        for name in LOADED_SERVICES.keys():
            MOCK_SERVICE_STATE[name] = get_initial_state_from_config(name)
    print(f"Initial mock state: {MOCK_SERVICE_STATE}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load services and state on startup
    print("Running startup tasks...")
    load_services_and_state()
    yield
    # Clean up if needed on shutdown
    print("Running shutdown tasks...")

app = FastAPI(lifespan=lifespan)

# --- Authentication / Session Dependency ---
def get_current_user(session: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None) -> str:
    if session is None:
        # No cookie, redirect to login
        raise HTTPException(status_code=307, detail="Not authenticated", headers={"Location": "/login"})
    try:
        # Validate the session cookie, max_age ensures it's not too old
        data = signer.loads(session, max_age=SESSION_MAX_AGE_SECONDS)
        username = data.get("username")
        if not username:
             raise HTTPException(status_code=307, detail="Invalid session data", headers={"Location": "/login"})
        return username # Successfully authenticated
    except (BadSignature, SignatureExpired):
        # Invalid or expired cookie, redirect to login
        response = RedirectResponse(url="/login?error=Session+expired+or+invalid", status_code=307)
        response.delete_cookie(SESSION_COOKIE_NAME) # Clear the bad cookie
        raise HTTPException(status_code=307, detail="Session expired or invalid", headers={"Location": "/login"})
    except Exception:
        # General error, treat as unauthenticated
        raise HTTPException(status_code=307, detail="Authentication error", headers={"Location": "/login"})

# --- Static Files and Templates ---
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# --- Routes ---
@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, error: str | None = None):
    """Display the login form."""
    return templates.TemplateResponse("login.html", {"request": request, "error": error})

@app.post("/login")
async def login_submit(username: Annotated[str, Form()], password: Annotated[str, Form()]):
    """Handle login form submission, create session cookie on success."""
    # Validate credentials (same logic as before, but no exception on failure)
    correct_username = secrets.compare_digest(
        username, os.environ.get("ADMIN_USER", "admin")
    )
    correct_password = secrets.compare_digest(
        password, os.environ.get("ADMIN_PASSWORD", "password")
    )

    if correct_username and correct_password:
        # Create session data and sign it
        session_data = signer.dumps({"username": username})
        # Redirect to main page, setting the session cookie
        response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=session_data,
            max_age=SESSION_MAX_AGE_SECONDS,
            httponly=True, # Prevent JS access
            samesite="lax" # Good default
        )
        print(f"User '{username}' logged in successfully.")
        return response
    else:
        # Invalid credentials, redirect back to login with error
        print(f"Login failed for user '{username}'.")
        return RedirectResponse(url="/login?error=Invalid+username+or+password", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/logout")
async def logout(response: Response):
    """Clear the session cookie and redirect to login."""
    print("User logged out.")
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, username: Annotated[str, Depends(get_current_user)], query: str | None = None):
    # Filter services based on query if provided
    service_data = []
    search_query = query.lower() if query else ""

    for name, path in sorted(LOADED_SERVICES.items()):
        # Basic case-insensitive search on display name
        if not search_query or search_query in name.lower():
            service_data.append({
                "display_name": name,
                "path": path,
                "is_enabled": MOCK_SERVICE_STATE.get(name, False)
                # Add other placeholder data here if needed for template
            })

    return templates.TemplateResponse(
        "index.html",
        {"request": request, "services": service_data, "username": username}
        # Query param is available via request.query_params in template if needed elsewhere
    )

@app.post("/toggle/{service_display_name}")
async def toggle_service_route(
    service_display_name: str,
    enabled: Annotated[str | None, Form()] = None, # Checkbox sends 'on' if checked, None if not
    username: Annotated[str, Depends(get_current_user)] = None # Protect endpoint
):
    if service_display_name not in LOADED_SERVICES:
        raise HTTPException(status_code=404, detail="Service not found")

    new_state = (enabled == "on") # Checkbox value is 'on' when checked
    MOCK_SERVICE_STATE[service_display_name] = new_state
    print(f"Simulated toggle for '{service_display_name}' to {new_state} by user '{username}'")

    # Redirect back to the main page (preserve query if present? Optional)
    # For simplicity, just redirect to root for now.
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/rescan")
async def rescan_services_route(
    request: Request, # Need request to preserve query
    username: Annotated[str, Depends(get_current_user)] = None # Protect endpoint
):
    print(f"Rescan triggered by user '{username}'...")
    load_services_and_state() # Re-run discovery and state initialization
    return RedirectResponse(url=f"/?query={request.query_params.get('query', '')}", status_code=status.HTTP_303_SEE_OTHER) # Preserve search query


# --- Run (for local testing) ---
# Use: uvicorn main:app --reload
# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run("main:app", host="0.0.0.0", port=7860, reload=True) 