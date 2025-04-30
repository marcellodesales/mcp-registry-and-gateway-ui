# MCP Gateway Registry

This application provides a web interface and API for registering and managing backend services that can be proxied through a gateway (like Nginx). It allows viewing service status, descriptions, and toggling their availability (currently simulated).

## Prerequisites

*   Python 3.12+
*   [uv](https://github.com/astral-sh/uv) (or `pip`) for package management.

## Installation

1.  **Clone the repository (if you haven't already):**
    ```bash
    git clone <your-repo-url>
    cd mcp-gateway
    ```

2.  **Create and activate a virtual environment (recommended):**
    Using `venv` (standard Python):
    ```bash
    python -m venv .venv
    source .venv/bin/activate # On Windows use `.venv\Scripts\activate`
    ```
    Using `uv` (which handles environments automatically):
    You can skip explicit environment creation if you use `uv run`.

3.  **Install dependencies:** Dependencies are defined in `pyproject.toml`.

    Using `uv`:
    ```bash
    # Installs dependencies defined in pyproject.toml
    uv pip install .
    ```
    Using `pip`:
    ```bash
    # Installs dependencies defined in pyproject.toml
    pip install .
    ```

## Configuration

1.  **Environment Variables:** The application uses a `.env` file in the project root (`mcp-gateway/`) for configuration. Create this file if it doesn't exist:
    ```bash
    cp .env.example .env # If you create an example file
    # Or create it manually
    touch .env
    ```

2.  **Edit `.env`:** Add the following variables:
    ```dotenv
    # A strong, randomly generated secret key for session security
    SECRET_KEY='your_strong_random_secret_key'

    # Credentials for the web interface login
    ADMIN_USER='admin'
    ADMIN_PASSWORD='your_secure_password'
    ```
    *Replace the placeholder values with secure ones.*

3.  **Service Definitions:** Services are defined by JSON files in the `registry/servers/` directory. See existing files for the expected format. The application loads these on startup.

## Running the Application

**Using `uv run`:**

This command leverages `uv` to manage the environment and run the development server.

```bash
uv run uvicorn registry.main:app --reload --host 0.0.0.0 --port 7860
```
*   `--reload`: Enables auto-reload on code changes.
*   `--host 0.0.0.0`: Makes the server accessible on your network.
*   `--port 7860`: Specifies the port to run on.

**Using `uvicorn` directly (after installing dependencies and activating venv):**

```bash
uvicorn registry.main:app --reload --host 0.0.0.0 --port 7860
```

Once running, you can access the web interface at `http://<your-server-ip>:7860`.

## Project Structure

*   `registry/`: Contains the main FastAPI application (`main.py`).
    *   `servers/`: Stores JSON definitions for each registered service.
    *   `static/`: Static assets (CSS, JS, images).
    *   `templates/`: Jinja2 HTML templates.
*   `.env`: Configuration file (needs to be created).
*   `README.md`: This file.

## Registering New Services (API)

You can register new services programmatically by sending a POST request to the `/register` endpoint.

*   **URL:** `/register`
*   **Method:** `POST`
*   **Authentication:** Requires a valid session cookie obtained via login.
*   **Content-Type:** `application/x-www-form-urlencoded`
*   **Form Data:**
    *   `name`: (String) Display name of the service.
    *   `description`: (String) Description of the service.
    *   `path`: (String) URL path for the service (e.g., `/my-service`).
    *   `tags`: (String, Optional) Comma-separated list of tags.
    *   `num_tools`: (Integer, Optional, Default: 0) Number of tools.
    *   `num_stars`: (Integer, Optional, Default: 0) Number of stars.
    *   `is_python`: (Boolean, Optional, Default: false) Whether it's a Python service.
    *   `license`: (String, Optional, Default: "N/A") License information.

**Example using `curl` (after logging in via the browser to get a cookie):**

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