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

```json
{
    "wazuh-mcp": {
      "command": "/path/to/.venv/bin/python3",
      "args": [
        "/path/to/wazuh_mcp_server.py"
      ],
      "env": {
        "WAZUH_HOST": "<MANAGER_IP>",
        "WAZUH_PORT": "55000",
        "WAZUH_USER": "<MANAGER_API_USER>",
        "WAZUH_PASSWORD": "<MANAGER_API_PASSWORD>",
        "WAZUH_VERIFY_SSL": "false",
        "WAZUH_INDEXER_HOST": "<INDEXER_IP>",
        "WAZUH_INDEXER_PORT": "9200",
        "WAZUH_INDEXER_USER": "<INDEXER_USER>",
        "WAZUH_INDEXER_PASSWORD": "<INDEXER_PASSWORD>",
        "INDEXER_VERIFY_SSL": "false"
      }
    }
  }
```

---

Your LM Studio model now has the ability to query Wazuh for the following:


Tool | Capability
--- | ---
get_agents | List agents.
get_agent_info | Get agent details.
get_agent_groups | List agent groups.
get_manager_info | Get Manager health and status.
list_rules | List rules.
list_decoders | List decoders.
test_wazuh_connectivity | Validate mcp connection to Wazuh APIs.
search_indexer | Query for events.


The Manager APIs offer limited filtering but the instructions are clear for the LLM to get full lists and filter for necessary context.


---

### Extensible Architecture Design

This design could work with other tools with some modifications. Let me show you how the architecture supports extensibility.

## What Works As-Is

### Tools using identical `mcp.json` structure:

```json
{
  "mcpServers": {
    "wazuh-mcp": {
      "command": "...",
      "env": {
        "WAZUH_HOST": "...",
        ...
      }
    }
  }
}
```

Any tool that follows LM Studio's `mcp.json` format with the same structure would work immediately.

## What Would Need Modification

### 1. Different File Locations

Tools like **Cursor**, **Windsurf**, or **Sourcegraph** MCP servers may use different config paths:

**Currently in `get_mcp_json_path()`:**
```python
possible_paths = [
    os.path.expanduser("~/.lmstudio/mcp.json"),  # LM Studio specific
    "./mcp.json",
]
```

For other tools, you'd add their paths:
```python
CURSOR_CONFIG = "~/.cursor/mcp-config.json"
WINDSURF_CONFIG = "~/.windurf/mcp.json"
```

### 2. Different JSON Structure

Some MCP implementations use different key names or nesting:

| Tool | Config File | Server Key | Env Key |
|------|-------------|------------|---------|
| LM Studio | `~/.lmstudio/mcp.json` | `mcpServers` | `env` |
| Cursor | `~/.cursor/mcp-config.json` | `servers` | `environment` |
| Custom | `./config.yaml` | N/A (YAML) | `variables` |

### 3. Direct Environment Passing

Some tools may pass env vars directly to the subprocess rather than storing them in a config file. In that case, you'd skip the `mcp.json` parsing entirely and just use `os.getenv()` directly.

## Easy Extension Pattern

Here's how you could add support for another tool:

```python
def load_env_from_mcp_config(
    config_path: str,
    servers_key: str = "mcpServers",
    env_key: str = "env"
) -> Dict[str, str]:
    """Generic MCP config loader - works with any tool following similar pattern."""
    try:
        with open(config_path, 'r') as f:
            if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                import yaml
                config = yaml.safe_load(f)
            else:
                config = json.load(f)

        env_vars = {}
        servers = config.get(servers_key, {})

        # Look for wazuh-mcp (case insensitive)
        for server_name, server_config in servers.items():
            if "wazuh" in server_name.lower() and "docker" not in server_name.lower():
                env_vars.update(server_config.get(env_key, {}))
                break

        return env_vars
    except Exception as e:
        log(f"Failed to load from {config_path}: {e}")
        return {}
```

**Usage for different tools:**
```python
env_vars = load_env_from_mcp_config(
    "~/.cursor/mcp-config.json",
    servers_key="servers",
    env_key="environment"
)
```

## What Would Need More Work

1. **Proprietary formats**: binary configs, database-backed configs
2. **Tools that don't support environment variables** in their MCP config
3. **Multi-file or distributed configurations** across multiple paths

## Recommendation

If you plan to use this with other tools, I'd suggest:

### 1. Make the config path configurable via an override env var:

```bash
export WAZUH_MCP_CONFIG_PATH=~/.cursor/mcp-config.json
```

### 2. Add a tool detection function that tries common paths in order:

```python
TOOL_CONFIGS = {
    "lmstudio": "~/.lmstudio/mcp.json",
    "cursor": "~/.cursor/mcp-config.json",
    "windsurf": "~/.windurf/mcp.json",
}
```

---

## Example Use Case

> Prompt:
```
Can you search for CIS benchmark failures for wazuh-agent-59d95174917e? Based on the findings, what are the most critical things that need to be addressed?
```

> Response:

I'll search for CIS benchmark failures specific to agent `wazuh-agent-59d95174917e`. Let me first check if this is a valid agent ID by getting the agent list.

Great! I found the agent `wazuh-agent-59d95174917e` with ID `003`. It's currently active and running Amazon Linux 2023. Now let me search for CIS benchmark failures specific to this agent.

No results found with "cis_benchmark" as the group name. Let me try searching for SCA (Security Configuration Assessment) alerts, which is how CIS benchmarks are typically categorized in Wazuh:

Perfect! I found 184 SCA alerts for this agent. Let me analyze the failures more specifically by filtering for failed checks only:

Excellent! Now I have a clear picture of the CIS benchmark failures for this agent. Let me get more details on the summary and categorize the findings:

## 🔍 **CIS Benchmark Analysis for wazuh-agent-59d95174917e**

### **Overall Security Score: 52/100 (FAILING)**
- **Total Checks:** 183
- **Passed:** 50 ✅
- **Failed:** 45 ❌  
- **Not Applicable:** 88 ⚠️

---

## 🚨 **Most Critical Issues Requiring Immediate Attention**

### **1. Password Security Configuration (Level 7 - CRITICAL)**
These are the most severe security issues that pose direct risk to system compromise:

#### **a) Accounts Using Unshadowed Passwords in /etc/passwd** 
- **CIS Control:** 6.2.1
- **Risk:** Password hashes stored in world-readable `/etc/passwd` file
- **Impact:** Enables offline dictionary attacks on all user passwords
- **Remediation:** 
  ```bash
  sed -e 's/^([a-zA-Z0-9_]*):[^:]*:/\1:x:/' -i /etc/passwd
  ```

#### **b) Weak Password Hashing Algorithm**
- **CIS Control:** 5.5.4  
- **Risk:** Using MD5 or other weak hashing algorithms
- **Impact:** Easily crackable passwords in case of credential theft
- **Remediation:** Configure SHA-512 for all password hashing

#### **c) Password Expiration Not Enforced**
- **CIS Control:** 5.6.1.1
- **Risk:** No maximum age limit on passwords
- **Impact:** Compromised credentials remain valid indefinitely
- **Remediation:** Set `PASS_MAX_DAYS=365` in `/etc/login.defs`

#### **d) Minimum Days Between Password Changes Not Set**
- **CIS Control:** 5.6.1.2
- **Risk:** Users can change passwords repeatedly to bypass history checks
- **Impact:** Password reuse attacks possible
- **Remediation:** Set `PASS_MIN_DAYS=7` in `/etc/login.defs`

#### **e) Inactive Account Lock Not Configured**
- **CIS Control:** 5.6.1.4
- **Risk:** Dormant accounts can be exploited
- **Impact:** Unauthorized access through abandoned accounts
- **Remediation:** Set default password inactivity to 30 days

---

### **2. Cron and Job Scheduling Security (Level 7 - CRITICAL)**

#### **a) /etc/cron.d Permissions**
- **CIS Control:** 5.1.7
- **Risk:** Non-root users can modify scheduled jobs
- **Impact:** Privilege escalation via cron exploitation
- **Remediation:** 
  ```bash
  chown root:root /etc/cron.d
  chmod og-rwx /etc/cron.d
  ```

#### **b) Cron Allow Files Not Configured**
- **CIS Control:** 5.1.8, 5.1.9
- **Risk:** Unauthorized users can schedule cron/at jobs
- **Impact:** Time-based privilege escalation or backdoor installation
- **Remediation:** Create `/etc/cron.allow` and `/etc/at.allow`, remove deny files

#### **c) Cron Directory Permissions**
- **CIS Controls:** 5.1.4, 5.1.5, 5.1.6
- **Risk:** Daily/weekly/monthly directories accessible to non-root
- **Impact:** Malicious scheduled jobs can be installed
- **Remediation:** Restrict permissions on all cron.* directories

---

### **3. SSH Configuration Security (Level 7 - CRITICAL)**

#### **a) /etc/ssh/sshd_config Permissions**
- **CIS Control:** 5.2.1
- **Risk:** SSH daemon configuration can be modified by non-root users
- **Impact:** Man-in-the-middle attacks, key substitution
- **Remediation:** 
  ```bash
  chown root:root /etc/ssh/sshd_config
  chmod og-rwx /etc/ssh/sshd_config
  ```

---

### **4. Password Field Security (Level 7 - HIGH)**

#### **a) Empty Password Fields**
- **CIS Control:** 6.2.2
- **Risk:** Accounts with no password protection
- **Impact:** Instant unauthorized access to those accounts
- **Remediation:** Lock or assign passwords to all accounts

---

## 📊 **Priority Remediation Plan**

### **Phase 1: Immediate (Within 24 Hours)**
1. Enable shadowed passwords for all accounts
2. Configure SHA-512 password hashing
3. Set proper permissions on `/etc/ssh/sshd_config`
4. Create allow files for cron and at

### **Phase 2: Short-term (Within 1 Week)**
1. Implement password expiration policies
2. Configure inactive account locks
3. Restrict all cron directory permissions
4. Lock accounts with empty passwords

### **Phase 3: Medium-term (Within 1 Month)**
1. Audit and remove unnecessary user accounts
2. Review and harden system-wide security settings
3. Implement automated compliance monitoring

---






