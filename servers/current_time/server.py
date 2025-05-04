"""
This server provides an interface to get the current time in a specified timezone using the timeapi.io API.
"""

import os
import time
import random
import requests
import argparse
import logging
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d - PID:%(process)d - %(filename)s:%(lineno)d - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class TZ_Name(BaseModel):
    """Parameters for specifying the name of the timezone for which to find out the current time."""

    tz_name: str = Field(
        default="America/New_York",
        description="Name of the timezone for which to find out the current time",
    )


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


@mcp.tool()
def current_time_by_timezone(params: TZ_Name) -> str:
    """
    Get the current time for a specified timezone using the timeapi.io API.

    Args:
        params: TZ_Name object containing the timezone name

    Returns:
        str: JSON response from the API with current time information

    Raises:
        Exception: If the API request fails after maximum retries
    """
    url = "https://timeapi.io/api/time/current/zone"
    headers = {"accept": "application/json"}
    params_dict = {"timeZone": params.tz_name}

    # Retry configuration
    max_retries = 5
    base_delay = 1  # seconds
    max_delay = 30  # seconds

    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers, params=params_dict)
            response.raise_for_status()  # Raise an exception for 4XX/5XX responses

            # Return the JSON response as a string
            return response.text

        except requests.exceptions.RequestException as e:
            # Calculate backoff delay with jitter
            delay = min(base_delay * (2**attempt) + random.uniform(0, 1), max_delay)

            # If this was our last retry, raise the exception
            if attempt == max_retries - 1:
                raise Exception(
                    f"Failed to get time after {max_retries} attempts: {str(e)}"
                )

            logger.warning(f"Request failed (attempt {attempt + 1}/{max_retries}): {str(e)}")
            logger.info(f"Retrying in {delay:.2f} seconds...")

            # Wait before retrying
            time.sleep(delay)


@mcp.resource("config://app")
def get_config() -> str:
    """Static configuration data"""
    return "App configuration here"


def main():
    # Run the server with the specified transport from command line args
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
