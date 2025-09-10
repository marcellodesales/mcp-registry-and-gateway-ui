"""
This server provides an interface to get the current time in a specified timezone using the timeapi.io API.
"""

import os
import argparse
import logging
from datetime import datetime
from typing import Annotated

import pytz
from mcp.server.fastmcp import FastMCP
from pydantic import Field

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d - PID:%(process)d - %(filename)s:%(lineno)d - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def parse_arguments():
    """Parse command line arguments with defaults matching environment variables."""
    parser = argparse.ArgumentParser(description="Current Time MCP Server")

    parser.add_argument(
        "--port",
        type=str,
        default=os.environ.get("MCP_SERVER_LISTEN_PORT", "8000"),
        help="Port for the MCP server to listen on (default: 8000)",
    )

    parser.add_argument(
        "--transport",
        type=str,
        default=os.environ.get("MCP_TRANSPORT", "sse"),
        help="Transport type for the MCP server (default: sse)",
    )

    return parser.parse_args()


# Parse arguments at module level to make them available
args = parse_arguments()

# Initialize FastMCP server using parsed arguments
mcp = FastMCP("current_time", port=args.port)


@mcp.prompt()
def system_prompt_for_agent(location: str) -> str:
    """
    Generates a system prompt for an AI Agent that wants to use the current_time MCP server.

    This function creates a specialized prompt for an AI agent that wants to determine the current time in a specific timezone.
    The prompt instructs an model to provide the name of a timezone closest to the current location provided by the
    user so that the timezone name (such as America/New_York, Africa/Cairo etc.) can be passed as an input to the tools
    provided by the current_time MCP server.
    Args:
        location (str): The location of the user, which will be used to determine the timezone.

    Returns:
        str: A formatted system prompt for the AI Agent.
    """

    system_prompt = f"""
You are an expert AI agent that wants to use the current_time MCP server. You will be provided with the user's location as input.
You will need to determine the name of the timezone closest to the current location provided by the user so that the timezone name (such as America/New_York, Africa/Cairo etc.)
can be passed as an input to the tools provided by the current_time MCP server.

The user's location is: {location}
"""
    return system_prompt


def get_current_time_in_timezone(timezone_name):
    """
    Retrieves the current time in a specified timezone.

    Args:
        timezone_name: A string representing the timezone name (e.g., 'America/New_York', 'Europe/London').

    Returns:
        A datetime object representing the current time in the specified timezone, or None if the timezone is invalid.
    """
    try:
        timezone = pytz.timezone(timezone_name)
        current_time = datetime.now(timezone)
        return current_time
    except pytz.exceptions.UnknownTimeZoneError:
        return None


@mcp.tool()
def current_time_by_timezone(
    tz_name: Annotated[str, Field(
        default="America/New_York",
        description="Name of the timezone for which to find out the current time"
    )] = "America/New_York"
) -> str:
    """
    Get the current time for a specified timezone using the timeapi.io API.

    Args:
        tz_name: Name of the timezone for which to find out the current time (default: America/New_York)

    Returns:
        str: string representation of the current time in the %Y-%m-%d %H:%M:%S %Z%z format for the specified timezone.

    Raises:
        Exception: If the API request fails
    """

    try:
        timezone = pytz.timezone(tz_name)
        current_time = datetime.now(timezone)
        return current_time.strftime('%Y-%m-%d %H:%M:%S %Z%z')
    except Exception as e:
        return f"Error: {str(e)}"
    
@mcp.resource("config://app")
def get_config() -> str:
    """Static configuration data"""
    return "App configuration here"


def main():
    # Run the server with the specified transport from command line args
    mount_path = "/currenttime"
    mcp.run(transport=args.transport, mount_path=mount_path)
    logger.info(f"Server is running on port {args.port} with transport {args.transport}, mount path {mount_path}")


if __name__ == "__main__":
    main()
