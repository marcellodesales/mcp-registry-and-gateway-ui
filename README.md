# ⚠️ ACTIVE DEVELOPMENT - WORK IN PROGRESS ⚠️

> **WARNING**: This repository is under active development. Expect frequent updates and breaking changes as we improve functionality and refine APIs. We recommend pinning to specific versions for production use. Star the repository to track our progress!

![Under Construction](https://img.shields.io/badge/Status-Under%20Construction-yellow)
![Stability](https://img.shields.io/badge/API%20Stability-Experimental-orange)

# MCP Gateway Registry

This application provides a web interface and API for registering and managing backend MCP (Meta-Computation Protocol) services. It acts as a central registry, health monitor, and dynamic reverse proxy configuration generator for Nginx.

## Features

*   **Service Registration:** Register MCP services via JSON files or the web UI/API.
*   **Web UI:** Manage services, view status, and monitor health through a web interface.
*   **Authentication:** Secure login system for the web UI and API access.
*   **Health Checks:**
    *   Periodic background checks for enabled services (checks `/sse` endpoint).
    *   Manual refresh trigger via UI button or API endpoint.
*   **Real-time UI Updates:** Uses WebSockets to push health status, tool counts, and last-checked times to all connected clients.
*   **Dynamic Nginx Configuration:** Generates an Nginx reverse proxy configuration file (`registry/nginx_mcp_revproxy.conf`) based on registered services and their enabled/disabled state.
*   **MCP Tool Discovery:** Automatically fetches and displays the list of tools (name, description, schema) for healthy services using the MCP client library.
*   **Service Management:**
    *   Enable/Disable services directly from the UI.
    *   Edit service details (name, description, URL, tags, etc.).
*   **Filtering & Statistics:** Filter the service list in the UI (All, Enabled, Disabled, Issues) and view basic statistics.
*   **UI Customization:**
    *   Dark/Light theme toggle (persisted in local storage).
    *   Collapsible sidebar (state persisted in local storage).
*   **State Persistence:** Enabled/Disabled state is saved to `registry/server_state.json` (and ignored by Git).

## Prerequisites

*   Python 3.11+ (or compatible version supporting FastAPI and MCP Client)
*   [uv](https://github.com/astral-sh/uv) (recommended) or `pip` for package management.
*   Nginx (or another reverse proxy) installed and configured to use the generated configuration file.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <your-repo-url>
    cd mcp-gateway
    ```

2.  **Create and activate a virtual environment (recommended):**
    *   Using `venv`:
        ```bash
        python -m venv .venv
        source .venv/bin/activate  # Linux/macOS
        # .venv\Scripts\activate  # Windows
        ```
    *   `uv` handles environments automatically via `uv run` or `uv pip sync`.

3.  **Install dependencies:** (Defined in `pyproject.toml` and locked in `uv.lock`)
    *   Using `uv`:
        ```bash
        uv pip sync
        ```
    *   Using `pip`:
        ```bash
        pip install .
        ```

## Configuration

1.  **Environment Variables:** Create a `.env` file in the project root (`mcp-gateway/`).
    ```bash
    touch .env
    ```
    Add the following variables, replacing placeholders with secure values:
    ```dotenv
    # REQUIRED: A strong, randomly generated secret key for session security
    SECRET_KEY='your_strong_random_secret_key_32_chars_or_more'

    # REQUIRED: Credentials for the web interface login
    ADMIN_USER='admin'
    ADMIN_PASSWORD='your_secure_password'
    ```
    **⚠️ IMPORTANT:** Use a strong, unpredictable `SECRET_KEY` for production environments.

2.  **Service Definitions:** Services can be added via the UI after starting the application. Alternatively, you can manually create JSON files in the `registry/servers/` directory before the first run. Each file defines one service. Example (`my_service.json`):
    ```json
    {
      "server_name": "My Example Service",
      "description": "Provides example functionality.",
      "path": "/my-service",
      "proxy_pass_url": "http://localhost:8001",
      "tags": ["example", "test"],
      "num_tools": 0,
      "num_stars": 0,
      "is_python": true,
      "license": "MIT",
      "tool_list": []
    }
    ```

## Running the Application

1.  **Start the FastAPI server:**
    *   Using `uv`:
        ```bash
        uv run uvicorn registry.main:app --reload --host 0.0.0.0 --port 7860
        ```
    *   Using `uvicorn` directly (ensure virtual environment is active):
        ```bash
        uvicorn registry.main:app --reload --host 0.0.0.0 --port 7860
        ```
    *   `--reload`: Enables auto-reload for development. Remove for production.
    *   `--host 0.0.0.0`: Makes the server accessible on your network.
    *   `--port 7860`: Specifies the port.

2.  **Configure Nginx:**
    *   The application generates `registry/nginx_mcp_revproxy.conf` on startup.
    *   Ensure your Nginx instance is running and includes this configuration file in its main `nginx.conf` (e.g., using an `include` directive in the `http` block).
    *   Reload or restart Nginx to apply the configuration (`sudo nginx -s reload`).
    *   **Note:** Detailed Nginx setup is beyond the scope of this README. The generated file assumes Nginx is listening on a standard port (e.g., 80 or 443) and proxies requests starting with registered paths (e.g., `/my-service`) to the appropriate backend defined by `proxy_pass_url`.

3.  **Access the UI:** Open your web browser and navigate to the address where Nginx is serving the application (e.g., `http://<your-nginx-server-ip>`). You should be redirected to the login page at `/login` (served by the FastAPI app). *Direct access via port 7860 is primarily for the UI itself; service proxying relies on Nginx.*

## Usage

1.  **Login:** Use the `ADMIN_USER` and `ADMIN_PASSWORD` from your `.env` file.
2.  **Register Service:** Use the "Register New Service" form in the UI (or the API).
3.  **Manage Services:**
    *   Toggle the Enabled/Disabled switch. The Nginx config automatically comments/uncomments the relevant `location` block.
    *   Click "Modify" to edit service details.
    *   Click the refresh icon (🔄) in the card header to manually trigger a health check and tool list update for enabled services.
4.  **View Tools:** Click the tool count icon (🔧) in the card footer to open a modal displaying discovered tools and their schemas for healthy services.
5.  **Filter:** Use the sidebar links to filter the displayed services.

## Project Structure

*   `registry/`: Main FastAPI application (`main.py`).
    *   `servers/`: Stores JSON definitions for each registered service.
    *   `static/`: Static assets (CSS, JS, images).
    *   `templates/`: Jinja2 HTML templates (`index.html`, `login.html`, etc.).
    *   `server_state.json`: Stores the enabled/disabled state (created automatically, **ignored by Git**).
    *   `nginx_mcp_revproxy.conf`: Nginx config generated dynamically (**ignored by Git**).
    *   `nginx_template.conf`: Template used for Nginx config generation.
*   `.env`: Environment variables (local configuration, **ignored by Git**).
*   `.gitignore`: Specifies files ignored by Git.
*   `pyproject.toml`: Project metadata and dependencies.
*   `uv.lock`: Locked dependency versions (used by `uv`).
*   `README.md`: This file.
*   `LICENSE`: Project license file.

## API Endpoints (Brief Overview)

*   `POST /register`: Register a new service (form data).
*   `POST /toggle/{service_path}`: Enable/disable a service (form data).
*   `POST /edit/{service_path}`: Update service details (form data).
*   `GET /api/server_details/{service_path}`: Get full details for a service (JSON).
*   `GET /api/tools/{service_path}`: Get the discovered tool list for a service (JSON).
*   `POST /api/refresh/{service_path}`: Manually trigger a health check/tool update.
*   `GET /login`, `POST /login`, `POST /logout`: Authentication routes.
*   `WS /ws/health_status`: WebSocket endpoint for real-time updates.

*(Authentication via session cookie is required for most non-login routes)*

## Key Dependencies

<<<<<<< HEAD
```bash
curl -X POST http://localhost:7860/register \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Cookie: mcp_gateway_session=..." \
  --data-urlencode "name=My New Service" \
  --data-urlencode "description=A fantastic new service" \
  --data-urlencode "path=/new-service" \
  --data-urlencode "tags=new,experimental" \
  --data-urlencode "license=MIT" \
  --data-urlencode "is_python=true"
```

*(Remember to replace the cookie value)*

This will create a corresponding JSON file in `registry/servers/`. 
=======
*   FastAPI
*   Uvicorn
*   Jinja2
*   python-dotenv
*   itsdangerous (for session signing)
*   mcp.py (MCP Client Library) 
>>>>>>> 812e383 (docs: Update README to include new api endpoints)
