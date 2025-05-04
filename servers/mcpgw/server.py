"""
This server provides tools to interact with the MCP Gateway Registry API.
"""

import os
import httpx # Use httpx for async requests
import argparse
import asyncio # Added for locking
import logging
import json
import websockets # For WebSocket connections
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP
from typing import Dict, Any, Optional, ClassVar, List
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d - PID:%(process)d - %(filename)s:%(lineno)d - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

load_dotenv()  # Load environment variables from .env file

# Get Registry URL from environment variable (keep this one)
REGISTRY_BASE_URL = os.environ.get("REGISTRY_BASE_URL", "http://localhost:7860") # Default to localhost

if not REGISTRY_BASE_URL:
    raise ValueError("REGISTRY_BASE_URL environment variable is not set.")

# --- Global state for authentication ---
_session_cookie: Optional[str] = None
_auth_lock = asyncio.Lock()


class Constants(BaseModel):
    # Using ClassVar to define class-level constants
    DESCRIPTION: ClassVar[str] = "MCP Gateway Registry Interaction Server (mcpgw)"
    DEFAULT_MCP_TRANSPORT: ClassVar[str] = "sse"
    DEFAULT_MCP_SEVER_LISTEN_PORT: ClassVar[str] = "8003" # Default to a different port
    REQUEST_TIMEOUT: ClassVar[float] = 15.0 # Timeout for HTTP requests

    # Disable instance creation - optional but recommended for constants
    class Config:
        frozen = True  # Make instances immutable


def parse_arguments():
    """Parse command line arguments with defaults matching environment variables."""
    parser = argparse.ArgumentParser(description=Constants.DESCRIPTION)

    parser.add_argument(
        "--port",
        type=str,
        default=os.environ.get(
            "MCP_SERVER_LISTEN_PORT", Constants.DEFAULT_MCP_SEVER_LISTEN_PORT
        ),
        help=f"Port for the MCP server to listen on (default: {Constants.DEFAULT_MCP_SEVER_LISTEN_PORT})",
    )

    parser.add_argument(
        "--transport",
        type=str,
        default=os.environ.get("MCP_TRANSPORT", Constants.DEFAULT_MCP_TRANSPORT),
        help=f"Transport type for the MCP server (default: {Constants.DEFAULT_MCP_TRANSPORT})",
    )

    return parser.parse_args()


# Parse arguments at module level to make them available
args = parse_arguments()

# Initialize FastMCP server using parsed arguments
mcp = FastMCP("mcpgw", port=args.port) # Changed server name


# --- Pydantic Models for Credentials and Parameters ---

class Credentials(BaseModel):
    """Credentials for authentication with the registry API."""
    username: str = Field(..., description="Username for registry authentication")
    password: str = Field(..., description="Password for registry authentication")


# Pydantic classes for ServicePathParams and RegisterServiceParams have been removed
# as they are no longer needed. The parameters are now directly defined in the functions.


# --- Helper function for making requests to the registry (with authentication) ---
async def _call_registry_api(method: str, endpoint: str, credentials: Credentials, **kwargs) -> Dict[str, Any]:
    """
    Helper function to make async requests to the registry API.
    Handles authentication automatically.
    
    Args:
        method: HTTP method (GET, POST, etc.)
        endpoint: API endpoint path
        credentials: Credentials model with username and password
        **kwargs: Additional arguments to pass to the HTTP request
        
    Returns:
        Dict[str, Any]: JSON response from the API
    """
    global _session_cookie
    url = f"{REGISTRY_BASE_URL.rstrip('/')}{endpoint}"

    # Use a single client instance for potential connection pooling benefits
    async with httpx.AsyncClient(timeout=Constants.REQUEST_TIMEOUT) as client:

        # --- Authentication Check ---
        if _session_cookie is None:
            async with _auth_lock:
                # Double-check after acquiring the lock in case another coroutine finished auth
                if _session_cookie is None:
                    logger.info("No active session cookie. Attempting to authenticate with the registry...")
                    login_url = f"{REGISTRY_BASE_URL.rstrip('/')}/login"
                    logger.debug(f"login_url: {login_url}") # Debugging line
                    try:
                        login_response = await client.post(
                            login_url,
                            data={"username": credentials.username, "password": credentials.password},
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            follow_redirects=False # Don't follow 303
                        )
                        
                        # Don't raise for status here since 303 is expected and not an error
                        # Instead, check if it's either 200 or 303 (both are valid success responses)
                        if login_response.status_code not in [200, 303]:
                            login_response.raise_for_status()  # Will raise for other error codes
                        
                        # Log status for debugging
                        logger.debug(f"Login response status: {login_response.status_code}")
                        
                        # Extract cookie - check common session cookie names
                        cookie_value = login_response.cookies.get("mcp_gateway_session")
                        
                        # Also check response headers for Set-Cookie if not found in cookies
                        if not cookie_value and 'set-cookie' in login_response.headers:
                            cookie_header = login_response.headers['set-cookie']
                            logger.debug(f"Found Set-Cookie header: {cookie_header}")
                            # Try to extract session cookie from header
                            if 'mcp_gateway_session=' in cookie_header:
                                cookie_parts = cookie_header.split('mcp_gateway_session=')[1].split(';')[0]
                                cookie_value = cookie_parts.strip()
                                logger.debug(f"Extracted cookie from header: {cookie_value}")

                        if cookie_value:
                            _session_cookie = cookie_value
                            logger.info("Authentication successful. Session cookie obtained.")
                        else:
                            # Log the response headers and body for debugging if cookie is missing
                            logger.debug(f"Login response headers: {login_response.headers}")
                            logger.debug(f"Login response status: {login_response.status_code}")
                            try:
                                logger.debug(f"Login response body: {login_response.text[:100]}...")  # First 100 chars
                            except Exception:
                                logger.error("Could not read response body")
                            
                            # If it's a redirect, you might need to handle it manually
                            if login_response.status_code in (301, 302, 303, 307, 308):
                                redirect_url = login_response.headers.get("Location")
                                logger.debug(f"Got redirect to: {redirect_url}")
                                
                                # Optional: Follow the redirect manually to get the cookie
                                try:
                                    logger.debug(f"Manually following redirect to {redirect_url}")
                                    redirect_response = await client.get(
                                        redirect_url,
                                        follow_redirects=False
                                    )
                                    logger.debug(f"Redirect response status: {redirect_response.status_code}")
                                    
                                    # Check for cookie in redirect response
                                    cookie_value = redirect_response.cookies.get("mcp_gateway_session")
                                    if cookie_value:
                                        _session_cookie = cookie_value
                                        logger.info("Authentication successful after redirect. Session cookie obtained.")
                                    else:
                                        logger.debug(f"Redirect response headers: {redirect_response.headers}")
                                        logger.warning("Still no session cookie after redirect.")
                                except Exception as e:
                                    logger.error(f"Error following redirect: {e}")
                            
                            if _session_cookie is None:
                                logger.error("Authentication failed: 'mcp_gateway_session' cookie not found in response.")
                                raise Exception("Authentication failed: Session cookie not found.")

                    except httpx.HTTPStatusError as e:
                         # Provide more context on login failure
                         error_detail = f"HTTP Status {e.response.status_code}"
                         try:
                             # Try to get detail from JSON response if available
                             error_detail += f" - Detail: {e.response.json().get('detail', 'N/A')}"
                         except Exception:
                             pass # Ignore if response is not JSON
                         logger.error(f"Authentication failed: {error_detail}")
                         raise Exception(f"Authentication failed: {error_detail}") from e
                    except httpx.RequestError as e:
                         logger.error(f"Authentication failed: Could not connect to registry at {login_url}. Error: {e}")
                         raise Exception(f"Authentication failed: Request Error {e}") from e
                    except Exception as e: # Catch unexpected errors during login
                         logger.error(f"An unexpected error occurred during authentication: {e}")
                         raise Exception(f"An unexpected error occurred during authentication: {e}") from e

        # If still no cookie after attempting auth, something went wrong.
        if _session_cookie is None:
             raise Exception("Unable to proceed: Not authenticated with the registry.")

        # --- Make the actual API request with the cookie ---
        request_cookies = {"mcp_gateway_session": _session_cookie}
        kwargs['cookies'] = request_cookies # Add/overwrite cookies in kwargs

        try:
            logger.info(f"Calling Registry API: {method} {url}") # Log the actual call
            response = await client.request(method, url, **kwargs)
            response.raise_for_status() # Raise HTTPStatusError for bad responses (4xx or 5xx)

            # Handle cases where response might be empty (e.g., 204 No Content)
            if response.status_code == 204:
                return {"status": "success", "message": "Operation successful, no content returned."}
            return response.json()

        except httpx.HTTPStatusError as e:
            # Check if it's an authentication error (e.g., cookie expired/invalid)
            if e.response.status_code in [401, 403]:
                logger.warning(f"API call failed with {e.response.status_code}. Cookie might be invalid or expired. Clearing cookie for re-authentication on next call.")
                # Clear the cookie so the next call re-authenticates
                async with _auth_lock:
                    _session_cookie = None
                # Raise a specific error indicating auth failure during API call
                raise Exception(f"Registry API Authentication Error ({e.response.status_code}) for {method} {url}. Please retry.") from e
            else:
                # Handle other HTTP errors as before
                error_detail = "No specific error detail provided."
                try:
                    error_detail = e.response.json().get("detail", error_detail)
                except Exception:
                    pass
                raise Exception(f"Registry API Error ({e.response.status_code}): {error_detail} for {method} {url}") from e
        except httpx.RequestError as e:
            # Network or connection error during the API call
            raise Exception(f"Registry API Request Error: Failed to connect or communicate with {url}. Details: {e}") from e
        except Exception as e: # Catch other potential errors during API call
             raise Exception(f"An unexpected error occurred while calling the Registry API at {url}: {e}") from e


# --- MCP Tools ---

@mcp.tool()
async def toggle_service(
    service_path: str = Field(..., description="The unique path identifier for the service (e.g., '/fininfo'). Must start with '/'."),
    username: str = Field(..., description="Username for registry authentication"),
    password: str = Field(..., description="Password for registry authentication")
) -> Dict[str, Any]:
    """
    Toggles the enabled/disabled state of a registered MCP server in the gateway.

    Args:
        service_path: The unique path identifier for the service (e.g., '/fininfo'). Must start with '/'.
        username: Username for registry authentication.
        password: Password for registry authentication.

    Returns:
        Dict[str, Any]: Response from the registry API indicating success or failure.

    Raises:
        Exception: If the API call fails.
    """
    endpoint = f"/toggle/{service_path.lstrip('/')}" # Ensure path doesn't have double slash
    credentials = Credentials(username=username, password=password)
    return await _call_registry_api("POST", endpoint, credentials=credentials)


@mcp.tool()
async def register_service(
    server_name: str = Field(..., description="Display name for the server."),
    path: str = Field(..., description="Unique URL path prefix for the server (e.g., '/my-service'). Must start with '/'."),
    proxy_pass_url: str = Field(..., description="The internal URL where the actual MCP server is running (e.g., 'http://localhost:8001')."),
    description: Optional[str] = Field("", description="Description of the server."),
    tags: Optional[List[str]] = Field(None, description="Optional list of tags for categorization."),
    num_tools: Optional[int] = Field(0, description="Number of tools provided by the server."),
    num_stars: Optional[int] = Field(0, description="Number of stars/rating for the server."),
    is_python: Optional[bool] = Field(False, description="Whether the server is implemented in Python."),
    license: Optional[str] = Field("N/A", description="License information for the server."),
    username: str = Field(..., description="Username for registry authentication"),
    password: str = Field(..., description="Password for registry authentication")
) -> Dict[str, Any]:
    """
    Registers a new MCP server with the gateway.
    
    Args:
        server_name: Display name for the server.
        path: Unique URL path prefix for the server (e.g., '/my-service'). Must start with '/'.
        proxy_pass_url: The internal URL where the actual MCP server is running (e.g., 'http://localhost:8001').
        description: Description of the server.
        tags: Optional list of tags for categorization.
        num_tools: Number of tools provided by the server.
        num_stars: Number of stars/rating for the server.
        is_python: Whether the server is implemented in Python.
        license: License information for the server.
        username: Username for registry authentication.
        password: Password for registry authentication.
        
    Returns:
        Dict[str, Any]: Response from the registry API, likely including the registered server details.
        
    Raises:
        Exception: If the API call fails.
    """
    endpoint = "/register"
    # Extract username and password for credentials
    credentials = Credentials(username=username, password=password)
    
    # Convert tags list to comma-separated string if it's a list
    tags_str = ",".join(tags) if isinstance(tags, list) and tags is not None else tags
    
    # Create form data to send to the API
    form_data = {
        "name": server_name,  # Use 'name' as expected by the registry API
        "path": path,
        "proxy_pass_url": proxy_pass_url,
        "description": description if description is not None else "",
        "tags": tags_str if tags_str is not None else "",
        "num_tools": num_tools,
        "num_stars": num_stars,
        "is_python": is_python,
        "license": license  # The registry API uses alias="license" for license_str
    }
    # Remove None values
    form_data = {k: v for k, v in form_data.items() if v is not None}
    
    # Send as form data instead of JSON
    return await _call_registry_api("POST", endpoint, credentials=credentials, data=form_data)

@mcp.tool()
async def get_service_tools(
    service_path: str = Field(..., description="The unique path identifier for the service (e.g., '/fininfo'). Must start with '/'. Use '/all' to get tools from all registered servers."),
    username: str = Field(..., description="Username for registry authentication"),
    password: str = Field(..., description="Password for registry authentication")
) -> Dict[str, Any]:
    """
    Lists the tools provided by a specific registered MCP server.

    Args:
        service_path: The unique path identifier for the service (e.g., '/fininfo'). Must start with '/'.
                      Use '/all' to get tools from all registered servers.
        username: Username for registry authentication.
        password: Password for registry authentication.

    Returns:
        Dict[str, Any]: A list of tools exposed by the specified server.

    Raises:
        Exception: If the API call fails or the server cannot be reached.
    """
    endpoint = f"/api/tools/{service_path.lstrip('/')}"
    credentials = Credentials(username=username, password=password)
    return await _call_registry_api("GET", endpoint, credentials=credentials)

@mcp.tool()
async def refresh_service(
    service_path: str = Field(..., description="The unique path identifier for the service (e.g., '/fininfo'). Must start with '/'."),
    username: str = Field(..., description="Username for registry authentication"),
    password: str = Field(..., description="Password for registry authentication")
) -> Dict[str, Any]:
    """
    Triggers a refresh of the tool list for a specific registered MCP server.
    The registry will re-connect to the target server to get its latest tools.

    Args:
        service_path: The unique path identifier for the service (e.g., '/fininfo'). Must start with '/'.
        username: Username for registry authentication.
        password: Password for registry authentication.

    Returns:
        Dict[str, Any]: Response from the registry API indicating the result of the refresh attempt.

    Raises:
        Exception: If the API call fails.
    """
    endpoint = f"/api/refresh/{service_path.lstrip('/')}"
    credentials = Credentials(username=username, password=password)
    return await _call_registry_api("POST", endpoint, credentials=credentials)


@mcp.tool()
async def get_server_details(
    service_path: str = Field(..., description="The unique path identifier for the service (e.g., '/fininfo'). Must start with '/'. Use '/all' to get details for all registered servers."),
    username: str = Field(..., description="Username for registry authentication"),
    password: str = Field(..., description="Password for registry authentication")
) -> Dict[str, Any]:
    """
    Retrieves detailed information about a registered MCP server.
    
    Args:
        service_path: The unique path identifier for the service (e.g., '/fininfo'). Must start with '/'.
                      Use '/all' to get details for all registered servers.
        username: Username for registry authentication.
        password: Password for registry authentication.
        
    Returns:
        Dict[str, Any]: Detailed information about the specified server or all servers if '/all' is specified.
        
    Raises:
        Exception: If the API call fails or the server is not registered.
    """
    endpoint = f"/api/server_details/{service_path.lstrip('/')}"
    credentials = Credentials(username=username, password=password)
    return await _call_registry_api("GET", endpoint, credentials=credentials)


@mcp.tool()
async def healthcheck() -> Dict[str, Any]:
    """
    Retrieves health status information from all registered MCP servers via the registry's WebSocket endpoint.
    
    Returns:
        Dict[str, Any]: Health status information for all registered servers, including:
            - status: 'healthy' or 'disabled'
            - last_checked_iso: ISO timestamp of when the server was last checked
            - num_tools: Number of tools provided by the server
            
    Raises:
        Exception: If the WebSocket connection fails or the data cannot be retrieved.
    """
    try:
        # Connect to the WebSocket endpoint
        registry_ws_url = f"ws://localhost:7860/ws/health_status"
        logger.info(f"Connecting to WebSocket endpoint: {registry_ws_url}")
        
        async with websockets.connect(registry_ws_url) as websocket:
            # WebSocket connection established, wait for the health status data
            logger.info("WebSocket connection established, waiting for health status data...")
            response = await websocket.recv()
            
            # Parse the JSON response
            health_data = json.loads(response)
            logger.info(f"Received health status data for {len(health_data)} servers")
            
            return health_data
            
    except websockets.exceptions.WebSocketException as e:
        logger.error(f"WebSocket error: {e}")
        raise Exception(f"Failed to connect to health status WebSocket: {e}")
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {e}")
        raise Exception(f"Failed to parse health status data: {e}")
    except Exception as e:
        logger.error(f"Unexpected error retrieving health status: {e}")
        raise Exception(f"Unexpected error retrieving health status: {e}")


# --- Main Execution ---

def main():
    # Run the server with the specified transport from command line args
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()