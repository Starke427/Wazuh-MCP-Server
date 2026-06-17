# Wazuh-MCP-Server
Wazuh MCP Server python script  that can be ran locally for LM Studio integration. Just download, configure mcp.json variables, and start querying Wazuh.

---

1. Download 'wazuh_mcp_server.py' to a local directory.

2. Create a local python venv to isolate packages and install dependencies:

```python
python -m venv .venv
source .venv/bin/activate

pip install mcp requests
deactivate
```

3. Configure LM Studio's mcp.json with the following variables:

> This is typically located at ~/.lmstudio/mcp.json or can be accessed by opening the right-hand side panel and clicking '+ Install' under Integrations.

```python
{
    "wazuh-mcp": {
      "command": "/path/to/.venv/bin/python3",
      "args": [
        "/path/to/wazuh_mcp_server.py"
      ],
      "env": {
        "WAZUH_HOST": "<MANAGER_IP>",
        "WAZUH_PORT": "55000",
        "WAZUH_USER": "",
        "WAZUH_PASSWORD": "",
        "WAZUH_VERIFY_SSL": "false",
        "WAZUH_INDEXER_HOST": "<INDEXER_IP>",
        "WAZUH_INDEXER_PORT": "9200",
        "WAZUH_INDEXER_USER": "",
        "WAZUH_INDEXER_PASSWORD": "",
        "INDEXER_VERIFY_SSL": "false"
      }
    }
  }
}
```

