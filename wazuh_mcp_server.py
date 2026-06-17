#!/usr/bin/env python3
"""
Wazuh MCP Server for LM Studio - Updated with Manager API & Indexer support

This server provides Model Context Protocol (MCP) tools to query the Wazuh Manager API and Indexer.
Updated based on: https://documentation.wazuh.com/current/user-manual/api/reference.html and https://documentation.wazuh.com/current/user-manual/indexer-api/reference.html

"""

import os
import sys
import json
import time
import base64
import requests
from typing import Optional, Dict, Any, List
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Tool,
    TextContent,
    ListToolsResult,
    CallToolResult,
)


# Configuration - loaded dynamically from LM Studio mcp.json (no hardcoded defaults)
WAZUH_HOST = os.getenv("WAZUH_HOST")
WAZUH_PORT = os.getenv("WAZUH_PORT")
WAZUH_USER = os.getenv("WAZUH_USER")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD")
WAZUH_VERIFY_SSL = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"

# Wazuh Indexer configuration (can be different from Manager)
INDEXER_HOST = os.getenv("WAZUH_INDEXER_HOST")
INDEXER_PORT = os.getenv("WAZUH_INDEXER_PORT")
INDEXER_USER = os.getenv("WAZUH_INDEXER_USER")
INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD")
INDEXER_VERIFY_SSL = os.getenv("INDEXER_VERIFY_SSL", "false").lower() == "true"

# Validate that required Wazuh Manager variables are set
REQUIRED_WAZUH_VARS = ["WAZUH_HOST", "WAZUH_PORT", "WAZUH_USER", "WAZUH_PASSWORD"]
MISSING_WAZUH_VARS = [var for var in REQUIRED_WAZUH_VARS if not os.getenv(var)]
if MISSING_WAZUH_VARS:
    log(f"ERROR: Missing required Wazuh Manager environment variables: {', '.join(MISSING_WAZUH_VARS)}", level="ERROR")
    log("These must be set in the 'wazuh-mcp' server config in ~/.lmstudio/mcp.json under the 'env' section", level="ERROR")
    sys.exit(1)

# Validate that required Indexer variables are set (at minimum host and port)
REQUIRED_INDEXER_VARS = ["WAZUH_INDEXER_HOST", "WAZUH_INDEXER_PORT"]
MISSING_INDEXER_VARS = [var for var in REQUIRED_INDEXER_VARS if not os.getenv(var)]
if MISSING_INDEXER_VARS:
    log(f"ERROR: Missing required Indexer environment variables: {', '.join(MISSING_INDEXER_VARS)}", level="ERROR")
    log("These must be set in the 'wazuh-mcp' server config in ~/.lmstudio/mcp.json under the 'env' section", level="ERROR")
    sys.exit(1)

# Indexer API base URL construction (handle both http:// and bare hostname formats)
if INDEXER_HOST:
    if INDEXER_HOST.startswith("http"):
        INDEXER_HOSTNAME = INDEXER_HOST.replace("https://", "").replace("http://", "")
    else:
        INDEXER_HOSTNAME = INDEXER_HOST
else:
    log("ERROR: WAZUH_INDEXER_HOST is empty or not set", level="ERROR")
    sys.exit(1)

INDEXER_BASE_URL = f"https://{INDEXER_HOSTNAME}:{INDEXER_PORT}"

# API base URL construction (handle both http:// and bare hostname formats)
if WAZUH_HOST:
    if WAZUH_HOST.startswith("http"):
        HOSTNAME = WAZUH_HOST.replace("https://", "").replace("http://", "")
    else:
        HOSTNAME = WAZUH_HOST
else:
    log("ERROR: WAZUH_HOST is empty or not set", level="ERROR")
    sys.exit(1)

API_BASE_URL = f"https://{HOSTNAME}:{WAZUH_PORT}"


# Validate API URLs were constructed successfully
if not INDEXER_BASE_URL or ":" not in INDEXER_BASE_URL:
    log(f"ERROR: Could not construct valid Indexer base URL from WAZUH_INDEXER_HOST={INDEXER_HOST} and WAZUH_INDEXER_PORT={INDEXER_PORT}", level="ERROR")
    sys.exit(1)

if not API_BASE_URL or ":" not in API_BASE_URL:
    log(f"ERROR: Could not construct valid API base URL from WAZUH_HOST={WAZUH_HOST} and WAZUH_PORT={WAZUH_PORT}", level="ERROR")
    sys.exit(1)


# JWT token cache
JWT_TOKEN: Optional[str] = None
TOKEN_EXPIRY: float = 0


def log(message: str, level: str = "INFO") -> None:
    """Log messages to stderr for MCP server debugging."""
    print(f"[{level}] {message}", file=sys.stderr, flush=True)


def get_mcp_json_path() -> Optional[str]:
    """Find LM Studio's mcp.json file in a user-agnostic way.
    
    Checks multiple locations in order of preference:
    1. ~/.lmstudio/mcp.json (user's home directory via expanduser)
    2. ./mcp.json relative to script location
    
    Returns the first valid path found that contains mcpServers, or None if not found.
    """
    possible_paths = [
        os.path.expanduser("~/.lmstudio/mcp.json"),
        "./mcp.json",
        os.path.join(os.path.dirname(__file__), "mcp.json"),
    ]
    
    for mcp_path in possible_paths:
        if os.path.exists(mcp_path):
            try:
                with open(mcp_path, 'r') as f:
                    config = json.load(f)
                # Verify it's a valid LM Studio MCP config file
                if "mcpServers" in config and isinstance(config["mcpServers"], dict):
                    return mcp_path
            except (json.JSONDecodeError, IOError) as e:
                log(f"Failed to read/parse {mcp_path}: {e}", level="DEBUG")
                continue
    
    return None


def load_wazuh_env_from_mcp(mcp_path: str) -> Dict[str, str]:
    """Load environment variables from the 'wazuh-mcp' server config in LM Studio's mcp.json.
    
    This function specifically extracts ONLY the wazuh-mcp server's env vars,
    leaving other MCP servers (like Docker) untouched and not loading their env vars.
    
    Args:
        mcp_path: Path to the LM Studio mcp.json file
        
    Returns:
        Dictionary of environment variables from wazuh-mcp config
    """
    try:
        with open(mcp_path, 'r') as f:
            mcp_config = json.load(f)
        
        env_vars = {}
        
        # Only extract vars from the 'wazuh-mcp' server (not all servers)
        if "mcpServers" in mcp_config and isinstance(mcp_config["mcpServers"], dict):
            
            # Check for exact match first
            wazuh_server = mcp_config["mcpServers"].get("wazuh-mcp")
            
            # Also check case variations or similar names (but not Docker)
            if not wazuh_server:
                for key in mcp_config["mcpServers"]:
                    key_lower = key.lower()
                    if "wazuh" in key_lower and "docker" not in key_lower:
                        wazuh_server = mcp_config["mcpServers"][key]
                        log(f"Found wazuh-mcp config via alternative name: {key}", level="DEBUG")
                        break
            
            if isinstance(wazuh_server, dict) and "env" in wazuh_server:
                for key, value in wazuh_server["env"].items():
                    env_vars[key] = str(value)
        
        return env_vars
        
    except json.JSONDecodeError as e:
        log(f"Failed to parse mcp.json at {mcp_path}: {e}", level="WARNING")
        return {}
    except Exception as e:
        log(f"Error reading mcp.json from {mcp_path}: {type(e).__name__}: {e}", level="WARNING")
        return {}


def load_environment_variables():
    """Load environment variables from LM Studio's mcp.json.
    
    This function ensures the script works regardless of which user runs it,
    by finding LM Studio's mcp.json in a user-agnostic way.
    
    Priority order:
    1. Already-set OS environment variables (highest priority - don't override)
    2. Variables from wazuh-mcp server config in ~/.lmstudio/mcp.json
    
    Note: We intentionally do NOT load Docker MCP settings here, as those are
    for a different MCP server and should not affect this script's configuration.
    
    This function is called at module import time to ensure variables are available
    before any other code runs.
    """
    
    # Check if we're already running with env vars set (e.g., by LM Studio)
    if all(var in os.environ for var in ["WAZUH_HOST", "WAZUH_USER"]):
        log("Environment variables already set by OS/LM Studio, skipping mcp.json load")
        return
    
    # Try to find and load from LM Studio's mcp.json
    mcp_path = get_mcp_json_path()
    
    if mcp_path:
        log(f"Found MCP config at {mcp_path}")
        wazuh_env_vars = load_wazuh_env_from_mcp(mcp_path)
        
        if wazuh_env_vars:
            log(f"Loaded {len(wazuh_env_vars)} variables from wazuh-mcp server config:")
            for key in sorted(wazuh_env_vars.keys()):
                # Mask sensitive values in logs
                value = wazuh_env_vars[key]
                if "PASSWORD" in key or "SECRET" in key:
                    masked_value = "***REDACTED***"
                    log(f"  {key}: {masked_value}")
                else:
                    log(f"  {key}: {value}")
            
            # Set environment variables (only if not already set)
            for key, value in wazuh_env_vars.items():
                if key not in os.environ:
                    os.environ[key] = value
            
            return
    
    log("WARNING: Could not load environment variables from mcp.json", level="WARNING")
    log("Please ensure ~/.lmstudio/mcp.json exists with 'wazuh-mcp' server config under the 'env' section", level="WARNING")


# Load environment variables at module import time (before any other code)
load_environment_variables()


def get_jwt_token() -> Optional[str]:
    """Obtain JWT token from Wazuh API using HTTP Basic Authentication."""
    global JWT_TOKEN, TOKEN_EXPIRY
    
    current_time = time.time()
    if JWT_TOKEN and TOKEN_EXPIRY > current_time + 60:
        return JWT_TOKEN
    
    log(f"Attempting to obtain JWT token (user={WAZUH_USER}) using Basic Auth")
    
    try:
        auth_string = f"{WAZUH_USER}:{WAZUH_PASSWORD}"
        encoded_credentials = base64.b64encode(auth_string.encode()).decode()
        
        response = requests.post(
            f"{API_BASE_URL}/security/user/authenticate",
            headers={
                "Authorization": f"Basic {encoded_credentials}"
            },
            verify=WAZUH_VERIFY_SSL,
            timeout=10
        )
        
        log(f"Auth response status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            data = result.get("data", {}) if isinstance(result, dict) else {}
            JWT_TOKEN = data.get("token")
            
            if JWT_TOKEN:
                TOKEN_EXPIRY = current_time + 3540
                log(f"✓ JWT token obtained successfully (valid for {TOKEN_EXPIRY - current_time:.0f}s)")
                return JWT_TOKEN
        
        elif response.status_code == 401:
            try:
                error_data = response.json()
                detail = error_data.get("detail", "Invalid credentials") if isinstance(error_data, dict) else str(error_data)
            except:
                detail = "Invalid credentials"
            log(f"Authentication failed with 401: {detail}", level="ERROR")
        
        else:
            log(f"Unexpected response status: {response.status_code}", level="WARNING")
            
    except requests.exceptions.Timeout as e:
        log(f"Authentication request timeout: {e}", level="ERROR")
    except Exception as e:
        log(f"Error during authentication: {type(e).__name__}: {e}", level="ERROR")
    
    return None


def get_indexer_auth_token() -> Optional[str]:
    """Obtain JWT token from Wazuh Manager API for Indexer access using HTTP Basic Auth.
    
    The Wazuh Indexer uses the same security system as the Manager, so we obtain
    a JWT token and use it to authenticate against the Indexer API.
    """
    global JWT_TOKEN
    
    # Reuse existing JWT if valid, otherwise obtain new one
    current_time = time.time()
    if not JWT_TOKEN or TOKEN_EXPIRY <= current_time:
        JWT_TOKEN = get_jwt_token()
    
    return JWT_TOKEN


def make_indexer_request(
    endpoint: str, 
    method: str = "GET", 
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    require_auth: bool = True,
    timeout: int = 30
) -> Optional[Dict[str, Any]]:
    """Make request to Wazuh Indexer API using Basic Auth.
    
    The Wazuh Indexer (OpenSearch) uses HTTP Basic Authentication directly,
    unlike the Manager API which requires JWT tokens.
    """
    url = f"{INDEXER_BASE_URL}{endpoint}"
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    if require_auth:
        # Use Basic Auth directly for Indexer (OpenSearch)
        auth_string = f"{INDEXER_USER}:{INDEXER_PASSWORD}"
        encoded_credentials = base64.b64encode(auth_string.encode()).decode()
        headers["Authorization"] = f"Basic {encoded_credentials}"
    
    try:
        response = requests.request(
            method, url, params=params, data=json.dumps(data) if data else None,
            headers=headers, verify=INDEXER_VERIFY_SSL, timeout=timeout
        )
        
        log(f"Indexer request: {method} {endpoint} -> {response.status_code}")
        
        if response.status_code in [200, 201]:
            try:
                result = response.json()
                return result
            except json.JSONDecodeError as e:
                log(f"Failed to parse JSON response: {e}", level="ERROR")
                return None
        
        elif response.status_code == 401:
            log("Indexer request failed with 401 - check credentials", level="ERROR")
            try:
                error_data = response.json()
                message = error_data.get("error", {}).get("reason", "Authentication failed") if isinstance(error_data, dict) else str(response.text)
            except:
                message = "Authentication failed"
            return {"error": True, "status_code": 401, "message": message}
        
        else:
            log(f"Indexer request failed with status {response.status_code}", level="ERROR")
            try:
                error_data = response.json()
                message = error_data.get("message", str(error_data)) if isinstance(error_data, dict) else str(error_data)
                return {"error": True, "status_code": response.status_code, "message": message}
            except:
                return {"error": True, "status_code": response.status_code, "message": f"API error ({response.status_code})"}
                
    except requests.exceptions.Timeout as e:
        log(f"Indexer request timeout: {e}", level="ERROR")
        return {"error": True, "message": "Request timed out"}
        
    except requests.exceptions.ConnectionError as e:
        log(f"Indexer connection error: {e}", level="ERROR")
        return {"error": True, "message": f"Connection failed: {str(e)}"}
        
    except Exception as e:
        log(f"Unexpected Indexer error: {type(e).__name__}: {e}", level="ERROR")
        return {"error": True, "message": str(e)}


def make_api_request(
    endpoint: str, 
    method: str = "GET", 
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    require_auth: bool = True,
    verbose: bool = False
) -> Optional[Dict[str, Any]]:
    """Make authenticated request to Wazuh API."""
    url = f"{API_BASE_URL}{endpoint}"
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    if require_auth:
        global JWT_TOKEN
        if not JWT_TOKEN or time.time() >= TOKEN_EXPIRY:
            JWT_TOKEN = get_jwt_token()
        
        if JWT_TOKEN:
            headers["Authorization"] = f"Bearer {JWT_TOKEN}"
        else:
            log("Cannot make API request without valid JWT token", level="ERROR")
            return None
    
    try:
        response = requests.request(
            method, url, params=params, data=json.dumps(data) if data else None,
            headers=headers, verify=WAZUH_VERIFY_SSL, timeout=30
        )
        
        log(f"API request: {method} {endpoint} -> {response.status_code}")
        
        if response.status_code in [200, 204]:
            try:
                result = response.json()
                # Wazuh API returns data in 'affected_items' or 'data' field
                if isinstance(result, dict):
                    return result.get("data") or result.get("affected_items", []) or result
                return result
            except json.JSONDecodeError as e:
                log(f"Failed to parse JSON response: {e}", level="ERROR")
                return None
        
        elif response.status_code == 401:
            log("API request failed with 401 - token may be expired", level="WARNING")
            if require_auth:
                new_token = get_jwt_token()
                if new_token:
                    JWT_TOKEN = new_token
                    headers["Authorization"] = f"Bearer {new_token}"
                    response = requests.request(
                        method, url, params=params, data=json.dumps(data) if data else None,
                        headers=headers, verify=WAZUH_VERIFY_SSL, timeout=30
                    )
                    log(f"Retried API request after token refresh: {response.status_code}")
                    if response.status_code in [200, 204]:
                        try:
                            result = response.json()
                            return result.get("data") or result.get("affected_items", []) or result
                        except:
                            pass
            return None
        
        else:
            log(f"API request failed with status {response.status_code}", level="ERROR")
            try:
                error_data = response.json()
                message = error_data.get("message", str(error_data)) if isinstance(error_data, dict) else str(error_data)
                return {"error": True, "status_code": response.status_code, "message": message}
            except:
                return {"error": True, "status_code": response.status_code, "message": f"API error ({response.status_code})"}
                
    except requests.exceptions.Timeout as e:
        log(f"API request timeout: {e}", level="ERROR")
        return {"error": True, "message": "Request timed out"}
        
    except requests.exceptions.ConnectionError as e:
        log(f"API connection error: {e}", level="ERROR")
        return {"error": True, "message": f"Connection failed: {str(e)}"}
        
    except Exception as e:
        log(f"Unexpected API error: {type(e).__name__}: {e}", level="ERROR")
        return {"error": True, "message": str(e)}


# MCP Tool Definitions - Updated with correct Wazuh API parameter mappings
TOOLS = [
    Tool(
        name="get_agents",
        description="""List all agents and their status. Supports filtering by group and connection status.

Parameters:
- group_filter: Filter by agent group name (exact match)
- status_filter: Filter by status - values: 'active', 'disconnected', 'never_connected'
- limit: Max results to return (default: 10, max: 100)

Returns: Agent ID, name, IP, group, last connection time, registration date, OS details""",
        inputSchema={
            "type": "object",
            "properties": {
                "group_filter": {"type": "string", "description": "Filter agents by group name"},
                "status_filter": {"type": "string", "enum": ["active", "disconnected", "never_connected"], "description": "Filter agents by connection status"},
                "limit": {"type": "integer", "default": 10, "minimum": 1, "maximum": 100, "description": "Maximum number of agents to return"}
            },
            "required": []
        }
    ),
    Tool(
        name="get_agent_info",
        description="""Get detailed information about a specific agent.

Parameters:
- agent_id: Required - Agent ID (e.g., '001', '002'). Use get_agents first to find valid IDs.

Returns: Complete agent details including OS, version, IP, group, manager info, and registration data""",
        inputSchema={
            "type": "object",
            "properties": {
                "agent_id": {"type": "string", "description": "Required - Agent ID (e.g., '001')"}
            },
            "required": ["agent_id"]
        }
    ),
    Tool(
        name="get_agent_groups",
        description="""List all agent groups and their configuration.

Returns: Group IDs, names, number of agents per group""",
        inputSchema={"type": "object", "properties": {}, "required": []}
    ),
    Tool(
        name="get_manager_info",
        description="""Get Wazuh manager basic information including version, UUID, and server type.

Returns: Version (e.g., 'v4.14.5'), UUID, server type ('server' or 'worker'), max_agents limit, timezone info""",
        inputSchema={"type": "object", "properties": {}, "required": []}
    ),
    Tool(
        name="get_manager_status",
        description="""Get Wazuh manager process status including which services are running/stopped.

Returns: Process status for all Wazuh daemons (analysisd, apid, execd, monitord, etc.), showing running/stopped state""",
        inputSchema={"type": "object", "properties": {}, "required": []}
    ),
    Tool(
        name="list_rules",
        description="""List security rules configured in Wazuh with filtering options.

Parameters:
- rule_id: Filter by specific rule ID (numeric)
- level: Filter by severity level (0-15)
- status: Filter by status - 'enabled' or 'disabled'
- group: Filter by MITRE group
- limit: Max rules to return (default: 20, max: 100)

Returns: Rule ID, description, level, category, groups, PCI/GDPR compliance mappings""",
        inputSchema={
            "type": "object",
            "properties": {
                "rule_id": {"type": "integer", "description": "Filter by rule ID"},
                "level": {"type": "string", "description": "Filter by severity level (0-15)"},
                "status": {"type": "string", "enum": ["enabled", "disabled"], "description": "Filter by status"},
                "group": {"type": "string", "description": "Filter by MITRE group"},
                "limit": {"type": "integer", "default": 20, "minimum": 1, "maximum": 100, "description": "Maximum rules to return"}
            },
            "required": []
        }
    ),
    Tool(
        name="list_decoders",
        description="""List decoders configured in Wazuh with filtering options.

Parameters:
- decoder_name: Filter by specific decoder name
- status: Filter by status - 'enabled' or 'disabled'
- limit: Max decoders to return (default: 20, max: 100)

Returns: Decoder ID, name, regex patterns, order, parent relationships""",
        inputSchema={
            "type": "object",
            "properties": {
                "decoder_name": {"type": "string", "description": "Filter by decoder name"},
                "status": {"type": "string", "enum": ["enabled", "disabled"], "description": "Filter by status"},
                "limit": {"type": "integer", "default": 20, "minimum": 1, "maximum": 100, "description": "Maximum decoders to return"}
            },
            "required": []
        }
    ),
    Tool(
        name="test_wazuh_connectivity",
        description="""Test connectivity to Wazuh API. Provides verbose diagnostic information including authentication status, endpoint availability, and error details. Use this tool when other tools fail or return errors.""",
        inputSchema={
            "type": "object",
            "properties": {
                "verbose": {"type": "boolean", "default": True, "description": "Enable verbose output with detailed error information"}
            },
            "required": []
        }
    ),
    Tool(
        name="search_indexer",
        description="""PRIMARY TOOL FOR SEARCHING WAZUH ALERTS AND EVENTS.

IMPORTANT: The Wazuh Manager API does NOT support searching alerts/events. Use this tool for ALL alert/event searches.

=== CRITICAL FIELD MAPPINGS (DISCOVERED FROM ACTUAL INDEX) ===
- rule.description: KEYWORD field (NOT text!)
  - Does NOT tokenize, use exact matches or wildcard/regexp queries
  - Use "wildcard": {"rule.description": "*keyword*"} for partial matching
  - Do NOT use match query expecting tokenization
  
- rule.groups: KEYWORD array field
  - Array of group names (e.g., ['ossec', 'sca'])
  - Use term query for exact group membership: {"term": {"rule.groups": "sca"}}
  
- rule.level: LONG (numeric) field
  - Integer values 0-15 representing severity
  - Use range queries: {"range": {"rule.level": {"gte": 8}}}
  - Do NOT use term query with string values

=== COMMON USE CASES WITH CORRECT QUERY PATTERNS ===

1. Partial text search in rule description (use WILDCARD, not match):
   {"wildcard": {"rule.description": "*sca*"}}
   
2. Full-text keyword search:
   {"term": {"rule.description.keyword": "exact phrase"}}
   
3. High-severity alerts (level >= 8):
   {"range": {"rule.level": {"gte": 8}}}

4. Alerts from specific group:
   {"term": {"rule.groups": "sca"}}

=== PARAMETERS ===
- index_pattern: Required - Index pattern (e.g., 'wazuh-alerts-*', 'wazuh-general-7.x')
- query_dsl: Optional - OpenSearch Query DSL object (bool, term, match, range). If not provided, uses match_all.
  IMPORTANT: For rule.level use range queries with integers or terms with numeric keys
- size: Optional - Max results to return (default: 10, max: 100)
- from_offset: Optional - Pagination offset for deep pagination (default: 0)
- sort_field: Optional - Field name to sort by (e.g., '@timestamp', 'rule.level')
- sort_order: Optional - 'asc' or 'desc' (default: 'desc')
- from_time: Optional - Start of time range in ISO format (e.g., '2026-01-01T00:00:00Z'). Adds range filter on @timestamp.
- to_time: Optional - End of time range in ISO format (e.g., '2026-01-31T23:59:59Z'). Adds range filter on @timestamp.
- aggs: Optional - Aggregation definitions for counting/grouping results. See OpenSearch aggregation DSL.
- highlight: Optional - Boolean to enable highlighting of matched terms (default: false)

=== EXAMPLE QUERIES ===

# Get 20 high-severity alerts (level >= 8) from last 7 days
{
  "index_pattern": "wazuh-alerts-*",
  "query_dsl": {
    "bool": {
      "must": [
        {"range": {"rule.level": {"gte": 8}}},
        {"range": {"@timestamp": {"gte": "now-7d"}}}
      ]
    }
  },
  "size": 20,
  "sort_field": "@timestamp",
  "sort_order": "desc"
}

# Count alerts by severity level (aggregation)
{
  "index_pattern": "wazuh-alerts-*",
  "aggs": {
    "by_level": {
      "terms": {"field": "rule.level", "size": 16}
    }
  },
  "size": 0
}

# Alerts from specific agent with high severity
{
  "index_pattern": "wazuh-alerts-*",
  "query_dsl": {
    "bool": {
      "must": [
        {"term": {"agent.id": "001"}},
        {"range": {"rule.level": {"gte": 8}}}
      ]
    }
  },
  "size": 20,
  "sort_field": "@timestamp",
  "sort_order": "desc"
}

# Full-text search in rule description (use WILDCARD for partial match)
{
  "index_pattern": "wazuh-alerts-*",
  "query_dsl": {"wildcard": {"rule.description": "*ssh*"}},
  "size": 10,
  "highlight": true
}

# Regular expression search in rule description
{
  "index_pattern": "wazuh-alerts-*",
  "query_dsl": {"regexp": {"rule.description": ".*cis.*benchmark.*"}},
  "size": 10
}

# Search by group membership (e.g., SCA alerts)
{
  "index_pattern": "wazuh-alerts-*",
  "query_dsl": {"term": {"rule.groups": "sca"}},
  "size": 20,
  "sort_field": "@timestamp"
}

# Time range with ISO format
{
  "index_pattern": "wazuh-alerts-*",
  "from_time": "2026-06-15T00:00:00Z",
  "to_time": "2026-06-16T23:59:59Z",
  "size": 20,
  "sort_field": "@timestamp"
}

# Combined boolean query with wildcard and range (MUST use list for 'must')
{
  "index_pattern": "wazuh-alerts-*",
  "query_dsl": {
    "bool": {
      "must": [
        {"wildcard": {"rule.description": "*failed*"}},
        {"range": {"rule.level": {"gte": 5}}}
      ]
    }
  },
  "size": 20,
  "sort_field": "@timestamp"
}

Returns: Search hits with _source documents, total count, aggregation buckets (if requested), execution time, and optional highlights. IMPORTANT: Boolean queries must have 'must' as a LIST/ARRAY to avoid attribute errors.""",
        inputSchema={
            "type": "object",
            "properties": {
                "index_pattern": {"type": "string", "description": "Required - Index pattern to search (e.g., 'wazuh-alerts-*', 'wazuh-general-7.x')"},
                "query_dsl": {"type": "object", "description": "Optional - OpenSearch Query DSL object (bool, term, match, range). IMPORTANT: For rule.level use range queries with integers or terms with numeric keys."},
                "size": {"type": "integer", "default": 10, "minimum": 1, "maximum": 100, "description": "Maximum number of results to return"},
                "from_offset": {"type": "integer", "default": 0, "minimum": 0, "description": "Pagination offset for deep pagination"},
                "sort_field": {"type": "string", "description": "Optional - Field name to sort by (e.g., '@timestamp', 'rule.level')"},
                "sort_order": {"type": "string", "enum": ["asc", "desc"], "default": "desc", "description": "Sort order for results"},
                "from_time": {"type": "string", "description": "Optional - Start of time range in ISO format (e.g., '2026-01-01T00:00:00Z'). Adds range filter on @timestamp."},
                "to_time": {"type": "string", "description": "Optional - End of time range in ISO format (e.g., '2026-01-31T23:59:59Z'). Adds range filter on @timestamp."},
                "aggs": {"type": "object", "description": "Optional - Aggregation definitions for counting/grouping results. See OpenSearch aggregation DSL."},
                "highlight": {"type": "boolean", "default": False, "description": "Enable highlighting of matched terms in results"}
            },
            "required": ["index_pattern"]
        }
    )
]


async def handle_list_tools() -> ListToolsResult:
    """Return available MCP tools."""
    return ListToolsResult(tools=TOOLS)


async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> CallToolResult:
    """Handle tool calls and return results to the LLM client."""
    
    try:
        if name == "get_agents":
            result = _handle_get_agents(arguments)
            
        elif name == "get_agent_info":
            result = _handle_get_agent_info(arguments)
            
        elif name == "get_agent_groups":
            result = _handle_get_agent_groups()
            
        elif name == "get_manager_info":
            result = _handle_get_manager_info()
            
        elif name == "get_manager_status":
            result = _handle_get_manager_status()
            
        elif name == "list_rules":
            result = _handle_list_rules(arguments)
            
        elif name == "list_decoders":
            result = _handle_list_decoders(arguments)
            
        elif name == "test_wazuh_connectivity":
            result = _handle_test_wazuh_connectivity(arguments)
            
        elif name == "search_indexer":
            result = _handle_search_indexer(arguments)
            
        else:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Unknown tool: {name}")],
                isError=True
            )
        
        if isinstance(result, dict):
            content_text = json.dumps(result, indent=2)
        else:
            content_text = str(result)
            
        return CallToolResult(
            content=[TextContent(type="text", text=content_text)],
            isError=False
        )
        
    except Exception as e:
        log(f"Error handling tool {name}: {type(e).__name__}: {e}", level="ERROR")
        return CallToolResult(
            content=[TextContent(type="text", text=f"Error: {str(e)}")],
            isError=True
        )


def _handle_get_agents(args: Dict[str, Any]) -> Dict[str, Any]:
    """Handle get_agents tool call with correct Wazuh API parameter mappings."""
    params = {}
    
    # Apply filters according to Wazuh API spec
    if args.get("group_filter"):
        params["group"] = args["group_filter"]  # Correct param name: 'group' not 'group_filter'
    
    if args.get("status_filter"):
        status_map = {
            "active": "active", 
            "disconnected": "disconnected", 
            "never_connected": "never_connected"
        }
        params["status"] = status_map.get(args["status_filter"], args["status_filter"])  # Correct param: 'status' not 'state'
    
    if args.get("limit"):
        limit = min(int(args["limit"]), 100)
        params["limit"] = limit
    
    log(f"Fetching agents with params: {params}")
    result = make_api_request("/agents", method="GET", params=params)
    
    if result is None:
        return {"error": True, "message": "Failed to fetch agents from Wazuh API"}
    
    # Wazuh API returns data wrapped in "data" -> "affected_items" structure
    if isinstance(result, dict):
        items = result.get("affected_items", []) or []
        total_count = result.get("total_affected_items", len(items))
    elif isinstance(result, list):
        items = result
        total_count = len(items)
    else:
        return {"error": True, "message": "Unexpected response format from Wazuh API"}
    
    limit = min(args.get("limit", 10), 100) if args.get("limit") else 10
    
    formatted_items = []
    for agent in items[:limit]:
        os_info = agent.get("os", {})
        if not isinstance(os_info, dict):
            os_info = {}
        
        # Handle groups as list or string
        group_value = agent.get("group") or (agent.get("groups", [None])[0] if isinstance(agent.get("groups"), list) else None)
        
        formatted = {
            "id": agent.get("id"),
            "name": agent.get("name"),
            "ip": agent.get("ip"),
            "group": group_value,
            "status": agent.get("status"),
            "last_connection": agent.get("lastKeepAlive"),
            "date_added": agent.get("dateAdd"),
            "os_name": os_info.get("name"),
            "os_version": os_info.get("version"),
            "os_build": os_info.get("build"),
            "kernel_version": os_info.get("uname", "").split("|")[2] if isinstance(os_info.get("uname"), str) else None,
            "architecture": os_info.get("arch") or os_info.get("platform"),
            "manager_ip": agent.get("registerIP"),
            "node_name": agent.get("node_name"),
        }
        formatted_items.append(formatted)
    
    return {
        "total_agents": total_count,
        "returned_count": len(formatted_items),
        "filtered_by": args,
        "filters_applied": params,
        "agents": formatted_items
    }


def _handle_get_agent_info(args: Dict[str, Any]) -> Dict[str, Any]:
    """Handle get_agent_info tool call."""
    agent_id = args.get("agent_id")
    
    if not agent_id:
        return {"error": True, "message": "Missing required parameter: agent_id"}
    
    result = make_api_request(f"/agents/{agent_id}", method="GET")
    
    if result is None:
        return {"error": True, "message": f"Failed to fetch agent {agent_id} from Wazuh API"}
    
    # Wazuh API returns data wrapped in "data" -> "affected_items" structure for single items too
    info = {}
    if isinstance(result, dict):
        affected_items = result.get("affected_items", [])
        if affected_items and isinstance(affected_items[0], dict):
            info = affected_items[0]
        else:
            # Check if "data" contains the agent directly
            data = result.get("data")
            if isinstance(data, dict) and "id" in data:
                info = data
    elif isinstance(result, list) and result:
        info = result[0] if isinstance(result[0], dict) else {}
    
    # Handle groups as list or string
    group_value = info.get("group") or (info.get("groups", [None])[0] if isinstance(info.get("groups"), list) else None)
    
    os_info = info.get("os", {})
    if not isinstance(os_info, dict):
        os_info = {}
    
    formatted_info = {
        "id": info.get("id"),
        "name": info.get("name"),
        "ip": info.get("ip"),
        "group": group_value,
        "status": info.get("status"),
        "version": info.get("version"),
        "os_name": os_info.get("name"),
        "os_version": os_info.get("version"),
        "last_connection": info.get("lastKeepAlive"),
        "date_added": info.get("dateAdd"),
        "manager_ip": info.get("registerIP"),
        "node_name": info.get("node_name"),
    }
    
    return formatted_info


def _handle_get_agent_groups() -> Dict[str, Any]:
    """Handle get_agent_groups tool call."""
    result = make_api_request("/groups", method="GET")
    
    if result is None:
        return {"error": True, "message": "Failed to fetch agent groups from Wazuh API"}
    
    # Wazuh API returns data wrapped in "data" -> "affected_items" structure
    items = []
    total_count = 0
    
    if isinstance(result, dict):
        items = result.get("affected_items", []) or []
        total_count = result.get("total_affected_items", len(items))
    elif isinstance(result, list):
        items = result
        total_count = len(items)
    
    formatted_items = []
    for group in items:
        if not isinstance(group, dict):
            continue
            
        formatted = {
            "id": group.get("id"),
            "name": group.get("name"),
            "count": group.get("count"),
        }
        formatted_items.append(formatted)
    
    return {
        "total_groups": total_count,
        "groups": formatted_items
    }


def _handle_get_manager_info() -> Dict[str, Any]:
    """Handle get_manager_info tool call - returns basic manager information."""
    result = make_api_request("/manager/info", method="GET")
    
    if result is None:
        return {"error": True, "message": "Failed to fetch manager info from Wazuh API"}
    
    # Wazuh API returns data wrapped in "data" -> "affected_items" structure
    items = []
    if isinstance(result, dict):
        items = result.get("affected_items", []) or []
    elif isinstance(result, list) and len(result) > 0:
        items = [result[0]] if isinstance(result[0], (dict, type(None))) else [result]
    
    if items and isinstance(items[0], dict):
        info = items[0]
        return {
            "version": info.get("version"),
            "uuid": info.get("uuid"),
            "type": info.get("type"),
            "max_agents": info.get("max_agents"),
            "openssl_support": info.get("openssl_support"),
            "timezone_offset": info.get("tz_offset"),
            "timezone_name": info.get("tz_name"),
        }
    
    return {"error": True, "message": "No manager info returned"}


def _handle_get_manager_status() -> Dict[str, Any]:
    """Handle get_manager_status tool call - returns process status."""
    result = make_api_request("/manager/status", method="GET")
    
    if result is None:
        return {"error": True, "message": "Failed to fetch manager status from Wazuh API"}
    
    # Wazuh API returns data wrapped in "data" -> "affected_items" structure
    items = []
    if isinstance(result, dict):
        items = result.get("affected_items", []) or []
    elif isinstance(result, list) and len(result) > 0:
        items = [result[0]] if isinstance(result[0], (dict, type(None))) else [result]
    
    if items and isinstance(items[0], dict):
        processes = items[0]
        
        # Categorize daemons by status
        running = [k for k, v in processes.items() if v == "running"]
        stopped = [k for k, v in processes.items() if v == "stopped"]
        
        return {
            "processes": processes,
            "summary": {
                "total_daemons": len(processes),
                "running_count": len(running),
                "stopped_count": len(stopped),
                "running": running,
                "stopped": stopped,
            }
        }
    
    return {"error": True, "message": "No process status returned"}


def _handle_list_rules(args: Dict[str, Any]) -> Dict[str, Any]:
    """Handle list_rules tool call."""
    params = {}
    
    if args.get("rule_id"):
        params["rule_id"] = str(args["rule_id"])
    if args.get("level"):
        params["level"] = args["level"]
    if args.get("status"):
        params["status"] = args["status"]
    if args.get("group"):
        params["group"] = args["group"]
    
    limit = min(args.get("limit", 20), 100) if args.get("limit") else 20
    params["limit"] = limit
    
    log(f"Listing rules with params: {params}")
    result = make_api_request("/rules", method="GET", params=params)
    
    if result is None:
        return {"error": True, "message": "Failed to fetch rules from Wazuh API"}
    
    # Wazuh API returns data wrapped in "data" -> "affected_items" structure
    items = []
    total_count = 0
    
    if isinstance(result, dict):
        items = result.get("affected_items", []) or []
        total_count = result.get("total_affected_items", len(items))
    elif isinstance(result, list):
        items = result
        total_count = len(items)
    
    formatted_items = []
    for rule in items[:limit]:
        if not isinstance(rule, dict):
            continue
            
        details = rule.get("details", {})
        if not isinstance(details, dict):
            details = {}
        
        groups_list = rule.get("groups", [])
        if not isinstance(groups_list, list):
            groups_list = []
        
        formatted = {
            "id": rule.get("id"),
            "filename": rule.get("filename"),
            "level": rule.get("level"),
            "status": rule.get("status"),
            "description": details.get("description", ""),
            "category": details.get("category", ""),
            "groups": groups_list,
            "pci_dss": details.get("pci_dss", []),
            "gdpr": details.get("gdpr", []),
        }
        formatted_items.append(formatted)
    
    return {
        "total_rules": total_count,
        "returned_count": len(formatted_items),
        "filters_applied": params,
        "rules": formatted_items
    }


def _handle_list_decoders(args: Dict[str, Any]) -> Dict[str, Any]:
    """Handle list_decoders tool call."""
    params = {}
    
    if args.get("decoder_name"):
        params["decoder_name"] = args["decoder_name"]
    if args.get("status"):
        params["status"] = args["status"]
    
    limit = min(args.get("limit", 20), 100) if args.get("limit") else 20
    params["limit"] = limit
    
    log(f"Listing decoders with params: {params}")
    result = make_api_request("/decoders", method="GET", params=params)
    
    if result is None:
        return {"error": True, "message": "Failed to fetch decoders from Wazuh API"}
    
    # Wazuh API returns data wrapped in "data" -> "affected_items" structure
    items = []
    total_count = 0
    
    if isinstance(result, dict):
        items = result.get("affected_items", []) or []
        total_count = result.get("total_affected_items", len(items))
    elif isinstance(result, list):
        items = result
        total_count = len(items)
    
    formatted_items = []
    for decoder in items[:limit]:
        if not isinstance(decoder, dict):
            continue
            
        details = decoder.get("details", {})
        if not isinstance(details, dict):
            details = {}
        
        regex_info = details.get("regex", {})
        if not isinstance(regex_info, dict):
            regex_info = {}
        
        formatted = {
            "id": decoder.get("position"),  # Position serves as ID
            "name": decoder.get("name"),
            "filename": decoder.get("filename"),
            "status": decoder.get("status"),
            "order": details.get("order", ""),
            "parent": details.get("parent"),
            "regex_pattern": regex_info.get("pattern", ""),
        }
        formatted_items.append(formatted)
    
    return {
        "total_decoders": total_count,
        "returned_count": len(formatted_items),
        "filters_applied": params,
        "decoders": formatted_items
    }


def _handle_test_wazuh_connectivity(args: Dict[str, Any]) -> Dict[str, Any]:
    """Handle test_wazuh_connectivity tool call - provides verbose diagnostic information."""
    
    results = {
        "test_name": "Wazuh MCP Server Connectivity Test",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "checks": {}
    }
    
    # Check 1: Environment Configuration
    results["checks"]["environment"] = {
        "host": WAZUH_HOST,
        "port": WAZUH_PORT,
        "user": WAZUH_USER,
        "verify_ssl": WAZUH_VERIFY_SSL,
        "api_base_url": API_BASE_URL
    }
    
    # Check 2: JWT Token Status
    results["checks"]["authentication"] = {
        "token_cached": bool(JWT_TOKEN),
        "status": "unknown"
    }
    
    # Try to get fresh token
    try:
        current_time = time.time()
        if not JWT_TOKEN or TOKEN_EXPIRY <= current_time:
            log("Attempting to obtain fresh JWT token...")
            
            auth_string = f"{WAZUH_USER}:{WAZUH_PASSWORD}"
            encoded_credentials = base64.b64encode(auth_string.encode()).decode()
            
            response = requests.post(
                f"{API_BASE_URL}/security/user/authenticate",
                headers={
                    "Authorization": f"Basic {encoded_credentials}"
                },
                verify=WAZUH_VERIFY_SSL,
                timeout=10
            )
            
            log(f"Auth response status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                data = result.get("data", {}) if isinstance(result, dict) else {}
                new_token = data.get("token")
                
                if new_token:
                    results["checks"]["authentication"]["status"] = "SUCCESS - Token obtained"
                    results["checks"]["authentication"]["token_length"] = len(new_token)
                    results["checks"]["authentication"]["expires_in_seconds"] = 3540
                else:
                    results["checks"]["authentication"]["status"] = "FAILED - No token in response"
            elif response.status_code == 401:
                try:
                    error_data = response.json()
                    detail = error_data.get("detail", "Invalid credentials") if isinstance(error_data, dict) else str(error_data)
                except:
                    detail = "Invalid credentials"
                results["checks"]["authentication"]["status"] = f"FAILED - 401 Unauthorized: {detail}"
            else:
                results["checks"]["authentication"]["status"] = f"FAILED - Unexpected status: {response.status_code}"
    except Exception as e:
        results["checks"]["authentication"]["status"] = f"FAILED - Exception: {type(e).__name__}: {str(e)}"
    
    # Check 3: Manager Info Endpoint
    try:
        manager_info_result = make_api_request("/manager/info", method="GET")
        if isinstance(manager_info_result, dict) or isinstance(manager_info_result, list):
            results["checks"]["manager_info"] = {
                "status": "SUCCESS",
                "available": True
            }
        else:
            results["checks"]["manager_info"] = {
                "status": f"FAILED - No data returned",
                "available": False
            }
    except Exception as e:
        results["checks"]["manager_info"] = {
            "status": f"FAILED - Exception: {type(e).__name__}: {str(e)}",
            "available": False
        }
    
    # Check 4: Agents Endpoint
    try:
        agents_result = make_api_request("/agents", method="GET")
        if isinstance(agents_result, dict) or isinstance(agents_result, list):
            items = agents_result.get("items", []) if isinstance(agents_result, (dict, list)) else []
            results["checks"]["agents_endpoint"] = {
                "status": "SUCCESS",
                "total_agents": agents_result.get("total_affected_items", len(items)) if isinstance(agents_result, dict) else len(items),
                "sample_agent_ids": [a.get("id") for a in items[:3]] if items else []
            }
        else:
            results["checks"]["agents_endpoint"] = {
                "status": f"FAILED - No data returned",
                "total_agents": 0
            }
    except Exception as e:
        results["checks"]["agents_endpoint"] = {
            "status": f"FAILED - Exception: {type(e).__name__}: {str(e)}",
            "total_agents": 0
        }
    
    # Summary
    all_checks_passed = all(
        check.get("status", "").startswith("SUCCESS") or 
        (isinstance(check, dict) and not any(k in str(check).lower() for k in ["failed", "error"]))
        for check in results["checks"].values() if isinstance(check, dict)
    )
    
    results["summary"] = {
        "overall_status": "ALL CHECKS PASSED" if all_checks_passed else "SOME CHECKS FAILED - See details above",
        "recommendations": []
    }
    
    # Generate recommendations based on failures
    if not results["checks"]["authentication"].get("status", "").startswith("SUCCESS"):
        results["summary"]["recommendations"].append(
            "Verify WAZUH_USER and WAZUH_PASSWORD environment variables are correct"
        )
    if not results.get("checks", {}).get("manager_info", {}).get("available", False):
        results["summary"]["recommendations"].append(
            f"Ensure Wazuh Manager is running at {API_BASE_URL}"
        )
    
    return results


def _handle_search_indexer(args: Dict[str, Any]) -> Dict[str, Any]:
    """Handle search_indexer tool call for Wazuh Indexer (OpenSearch) queries."""
    index_pattern = args.get("index_pattern")
    
    if not index_pattern:
        return {"error": True, "message": "Missing required parameter: index_pattern"}
    
    # Extract parameters with defaults
    size = min(args.get("size", 10), 100)
    from_offset = max(0, int(args.get("from_offset", 0)))
    sort_field = args.get("sort_field")
    sort_order = args.get("sort_order", "desc")
    
    # Build query DSL - use match_all if not provided
    query_dsl = args.get("query_dsl", {"match_all": {}})
    
    # Add time range filter if from_time or to_time provided
    if args.get("from_time") or args.get("to_time"):
        range_query = {}
        if args.get("from_time"):
            range_query["gte"] = args["from_time"]
        if args.get("to_time"):
            range_query["lte"] = args["to_time"]
        
        # Ensure the query is wrapped in a bool query with the time filter
        if not isinstance(query_dsl, dict) or "bool" not in query_dsl:
            query_dsl = {"bool": {"must": [query_dsl]}}
        else:
            must_clause = query_dsl.get("bool", {}).get("must", [])
            must_clause.append({"range": {"@timestamp": range_query}})
            query_dsl["bool"]["must"] = must_clause
    
    # Build search body
    search_body = {
        "from": from_offset,
        "size": size,
        "query": query_dsl
    }
    
    # Add sorting if specified
    if sort_field:
        search_body["sort"] = {sort_field: {"order": sort_order}}
    
    # Enable highlighting if requested
    highlight_fields = {}
    if args.get("highlight"):
        # Common Wazuh fields to highlight for security analysis
        highlight_fields = {
            "field": {"require_field_match": False, "number_of_fragments": 3}
        }
        search_body["highlight"] = highlight_fields
    
    # Add aggregations if specified
    aggs = args.get("aggs")
    if aggs:
        search_body["aggs"] = aggs
    
    log(f"Searching Indexer at {INDEXER_BASE_URL}/{index_pattern}/_search")
    log(f"Search body: {json.dumps(search_body, indent=2)}")
    
    result = make_indexer_request(
        f"/{index_pattern}/_search",
        method="POST",
        data=search_body,
        require_auth=True,
        timeout=60
    )
    
    if result is None:
        return {"error": True, "message": "Failed to search Indexer"}
    
    # Check for errors in the response
    if isinstance(result, dict) and result.get("error"):
        error_msg = result["error"].get("reason", str(result))
        log(f"Indexer query error: {error_msg}", level="ERROR")
        return {"error": True, "status_code": 400, "message": error_msg}
    
    # Format the response for readability
    hits = result.get("hits", {}).get("hits", [])
    formatted_hits = []
    
    for hit in hits:
        _source = hit.get("_source", {})
        highlight_result = hit.get("highlight", {}) if isinstance(hit, dict) else None
        
        # Build highlighted source for display
        highlighted_source = _source.copy() if isinstance(_source, dict) else {}
        if highlight_result and isinstance(highlight_result, dict):
            for field, fragments in highlight_result.items():
                if isinstance(fragments, list):
                    highlighted_source[f"{field}_highlighted"] = fragments[:2]  # First 2 matches
        
        formatted_hit = {
            "_index": hit.get("_index"),
            "_id": hit.get("_id"),
            "_score": hit.get("_score"),
            "_source": _source,
            "highlighted_source": highlighted_source if highlight_result else None,
            "timestamp": _source.get("@timestamp") if isinstance(_source, dict) else None
        }
        formatted_hits.append(formatted_hit)
    
    # Format aggregation results if present
    aggregations = None
    if result.get("aggregations"):
        aggregations = {
            key: {
                "doc_count_error_upper_bound": agg.get("doc_count_error_upper_bound"),
                "sum_other_doc_count": agg.get("sum_other_doc_count"),
                "buckets": [
                    {"key": bucket.get("key"), "doc_count": bucket.get("doc_count")}
                    for bucket in agg.get("buckets", [])[:20]  # Top 20 buckets
                ] if isinstance(agg.get("buckets"), list) else []
            }
            for key, agg in result["aggregations"].items()
        }
    
    return {
        "index_pattern": index_pattern,
        "from_offset": from_offset,
        "returned_count": len(formatted_hits),
        "total_hits": result.get("hits", {}).get("total", {}).get("value", len(hits)),
        "max_score": result.get("hits", {}).get("max_score"),
        "took_ms": result.get("took"),
        "timed_out": result.get("timed_out", False),
        "query_dsl_used": query_dsl,
        "aggregations": aggregations,
        "highlighting_enabled": bool(args.get("highlight")),
        "hits": formatted_hits
    }


async def main():
    """Run MCP server using stdio transport."""
    log("[Tools Provider.] Register with LM Studio")
    
    async with stdio_server() as (read_stream, write_stream):
        server = Server("wazuh-mcp", "1.0.0")
        
        # Set up handlers
        server.list_tools()(handle_list_tools)
        server.call_tool()(handle_call_tool)
        
        # Run the server
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
