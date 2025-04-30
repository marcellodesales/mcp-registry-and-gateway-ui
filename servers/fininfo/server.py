"""
This server provides stoack market data using the Polygon.io API.
"""

import os
import time
import requests
import argparse
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP
from typing import Dict, Any, Optional, ClassVar
from pydantic import validator
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file
API_KEY = os.environ.get("POLYGON_API_KEY")
if API_KEY is None:
    raise ValueError("POLYGON_API_KEY environment variable is not set.")


class Constants(BaseModel):
    # Using ClassVar to define class-level constants
    DESCRIPTION: ClassVar[str] = "Fininfo MCP Server"
    MAX_RETRIES: ClassVar[int] = 3
    DEFAULT_TIMEOUT: ClassVar[float] = 1
    DEFAULT_MCP_TRANSPORT: ClassVar[str] = "sse"
    DEFAULT_MCP_SEVER_LISTEN_PORT: ClassVar[str] = "8000"

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
mcp = FastMCP("fininfo", port=args.port)


class StockAggregateParams(BaseModel):
    """Parameters for retrieving stock aggregate data from Polygon.io API"""

    stock_ticker: str = Field(
        ..., description="Case-sensitive ticker symbol (e.g., 'AAPL')"
    )
    multiplier: int = Field(..., description="Size of the timespan multiplier")
    timespan: str = Field(..., description="Size of the time window")
    from_date: str = Field(
        ..., description="Start date in YYYY-MM-DD format or millisecond timestamp"
    )
    to_date: str = Field(
        ..., description="End date in YYYY-MM-DD format or millisecond timestamp"
    )
    adjusted: bool = Field(True, description="Whether results are adjusted for splits")
    sort: Optional[str] = Field(
        None, description="Sort results by timestamp ('asc' or 'desc')"
    )
    limit: int = Field(
        5000, description="Maximum number of base aggregates (max 50000)"
    )

    @validator("timespan")
    def validate_timespan(cls, v):
        valid_timespans = ["minute", "hour", "day", "week", "month", "quarter", "year"]
        if v not in valid_timespans:
            raise ValueError(f"Invalid timespan. Must be one of {valid_timespans}")
        return v

    @validator("sort")
    def validate_sort(cls, v):
        if v is not None and v not in ["asc", "desc"]:
            raise ValueError("Sort must be either 'asc', 'desc', or None")
        return v

    @validator("limit")
    def validate_limit(cls, v):
        if v > 50000:
            raise ValueError("Limit cannot exceed 50000")
        return v


@mcp.tool()
def get_stock_aggregates(params: StockAggregateParams) -> Dict[str, Any]:
    """
    Retrieve stock aggregate data from Polygon.io API.

    Args:
        params: StockAggregateParams object containing all required and optional parameters

    Returns:
        Dict[str, Any]: Response data from Polygon API

    Raises:
        requests.RequestException: If API call fails after retries
    """
    # Build URL and parameters
    base_url = "https://api.polygon.io"
    endpoint = f"/v2/aggs/ticker/{params.stock_ticker}/range/{params.multiplier}/{params.timespan}/{params.from_date}/{params.to_date}"
    url = f"{base_url}{endpoint}"

    # Prepare query parameters
    query_params = {"adjusted": str(params.adjusted).lower(), "apiKey": API_KEY}

    if params.sort:
        query_params["sort"] = params.sort

    if params.limit != 5000:  # Only add if not the default
        query_params["limit"] = params.limit

    # Make the API request with retries
    retry_count = 0
    while retry_count < Constants.MAX_RETRIES:
        try:
            response = requests.get(url, params=query_params)
            response.raise_for_status()  # Raise exception for 4XX/5XX responses

            # Return the JSON response
            return response.json()

        except requests.RequestException as e:
            retry_count += 1

            # If this was our last retry, raise the exception
            if retry_count == Constants.MAX_RETRIES:
                raise

            print(
                f"Request failed (attempt {retry_count}/{Constants.MAX_RETRIES}): {str(e)}"
            )
            print(f"Retrying in {Constants.RETRY_DELAY} seconds...")

            # Wait before retrying
            time.sleep(params.RETRY_DELAY)


@mcp.tool()
def print_stock_data(params: StockAggregateParams) -> str:
    """
    Format all fields from the Polygon.io stock aggregate response as a string.

    Args:
        params: StockAggregateParams object to fetch stock data

    Returns:
        str: Formatted string containing all stock data
    """
    # Initialize an empty string to collect all output
    output = []

    response_data = get_stock_aggregates(params)
    if not response_data:
        return "No data available"

    # Add response metadata
    output.append("\n=== Stock Aggregate Data ===")
    output.append(f"Ticker: {response_data.get('ticker', 'N/A')}")
    output.append(f"Adjusted: {response_data.get('adjusted', 'N/A')}")
    output.append(f"Query Count: {response_data.get('queryCount', 'N/A')}")
    output.append(f"Request ID: {response_data.get('request_id', 'N/A')}")
    output.append(f"Results Count: {response_data.get('resultsCount', 'N/A')}")
    output.append(f"Status: {response_data.get('status', 'N/A')}")

    # Add next_url if available
    if "next_url" in response_data:
        output.append(f"Next URL: {response_data.get('next_url')}")

    # Add detailed results
    results = response_data.get("results", [])
    if not results:
        output.append("\nNo result data available")
        return "\n".join(output)

    output.append(f"\nFound {len(results)} data points:")
    output.append(
        "\n{:<12} {:<10} {:<10} {:<10} {:<10} {:<12} {:<12} {:<10} {:<12}".format(
            "Timestamp",
            "Open",
            "High",
            "Low",
            "Close",
            "Volume",
            "VWAP",
            "Transactions",
            "OTC",
        )
    )
    output.append("-" * 105)

    for data in results:
        # Convert timestamp to readable date
        timestamp = data.get("t", 0)
        date_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(timestamp / 1000))

        # Format all the aggregate fields
        open_price = data.get("o", "N/A")
        high_price = data.get("h", "N/A")
        low_price = data.get("l", "N/A")
        close_price = data.get("c", "N/A")
        volume = data.get("v", "N/A")
        vwap = data.get("vw", "N/A")
        transactions = data.get("n", "N/A")
        otc = data.get("otc", False)

        output.append(
            "{:<12} {:<10.2f} {:<10.2f} {:<10.2f} {:<10.2f} {:<12.0f} {:<12.2f} {:<10} {:<12}".format(
                date_str,
                open_price if open_price != "N/A" else 0.0,
                high_price if high_price != "N/A" else 0.0,
                low_price if low_price != "N/A" else 0.0,
                close_price if close_price != "N/A" else 0.0,
                volume if volume != "N/A" else 0,
                vwap if vwap != "N/A" else 0.0,
                transactions if transactions != "N/A" else "N/A",
                otc,
            )
        )

    # Join all lines and return as a single string
    return "\n".join(output)


@mcp.resource("config://app")
def get_config() -> str:
    """Static configuration data"""
    return "App configuration here"


def main():
    # Run the server with the specified transport from command line args
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
