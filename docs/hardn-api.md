![HARDN Logo](assets/IMG_1233.jpeg)
# HARDN API

## Purpose

The HARDN API provides comprehensive overwatch and health monitoring for endpoints in distributed environments. It integrates with HARDN security services and the Legion monitoring daemon to enable real-time system monitoring, diagnostics, and management.

> **SSH port 22 is closed on HARDN-hardened systems.** Remote access is restricted to two channels only:
> - **Grafana dashboard** — port **9002** (visual monitoring)
> - **HARDN API** — port **8000** (programmatic access, documented here)

This server does not replace the **Grafana** endpoint system, but provides an open-source option for those interested in holistic monitoring within their own toolsets.

## Setup: Register Your SSH Public Key

Before the API will accept requests, your SSH public key must be added to `/etc/hardn/authorized_keys` on the server:

```bash
# On the HARDN server
sudo install -d -m 750 /etc/hardn
sudo install -m 640 /dev/null /etc/hardn/authorized_keys
cat ~/.ssh/id_ed25519.pub | sudo tee -a /etc/hardn/authorized_keys

# Restart the API service to pick up the new key
sudo systemctl restart hardn-api.service
```

Each line in `/etc/hardn/authorized_keys` holds one SSH public key (same format as `~/.ssh/authorized_keys`). Only keys listed here will be accepted — format-valid but unlisted keys are rejected with HTTP 401.

All API requests (except `GET /health`) require an SSH public key as a Bearer token. The key must be pre-registered in `/etc/hardn/authorized_keys` on the server — see **Setup** above.

### Generate a Key Pair (client side)

```bash
# Ed25519 is preferred
ssh-keygen -t ed25519 -C "hardn-api" -f ~/.ssh/hardn_api_key

# RSA 4096 also accepted
ssh-keygen -t rsa -b 4096 -C "hardn-api" -f ~/.ssh/hardn_api_key
```

**Keep the private key (`~/.ssh/hardn_api_key`) secret. Never share it.**

### Register the Public Key (server side)

```bash
cat ~/.ssh/hardn_api_key.pub | sudo tee -a /etc/hardn/authorized_keys
sudo systemctl restart hardn-api.service
```

### Transferring a Key from a Remote Machine

Because SSH (port 22) is closed, you cannot use `ssh-copy-id`. You have two practical options depending on whether you still have **temporary SSH access** during initial setup or not:

**Option A — During initial setup (SSH still open)**

Use this window before SSH is locked out to push the public key:

```bash
# On the CLIENT — copy the public key to the server's tmp directory
scp ~/.ssh/hardn_api_key.pub admin@your-server:/tmp/new_key.pub

# On the SERVER — append and secure
sudo tee -a /etc/hardn/authorized_keys < /tmp/new_key.pub
sudo rm /tmp/new_key.pub
sudo systemctl restart hardn-api.service
```

**Option B — Out-of-band (no SSH, air-gapped or already locked down)**

Physically or via an admin console, paste the public key directly:

```bash
# On the client — print the public key to copy it:
cat ~/.ssh/hardn_api_key.pub
# Output looks like:
# ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... hardn-api

# On the SERVER — paste it in as root:
sudo bash -c 'echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... hardn-api" >> /etc/hardn/authorized_keys'
sudo systemctl restart hardn-api.service
```

**Key exchange security rules:**

| Rule | Reason |
|------|--------|
| Only the **public key** (`.pub`) is ever transferred | The private key never leaves the client machine |
| Use `>>` (append), not `>` (overwrite) | Prevents wiping existing authorized keys |
| `chmod 600 /etc/hardn/authorized_keys` | Prevents other users from reading or modifying the keystore |
| Revoke access by removing that key's line from the file | Instant revocation — the private key becomes useless |

**Revoking a client key:**

```bash
# Remove the specific key by matching its comment or fingerprint
sudo grep -v "hardn-api" /etc/hardn/authorized_keys | sudo tee /etc/hardn/authorized_keys.tmp
sudo mv /etc/hardn/authorized_keys.tmp /etc/hardn/authorized_keys
sudo systemctl restart hardn-api.service
```

### Make Authenticated Requests

```bash
SSH_KEY=$(cat ~/.ssh/hardn_api_key.pub)

# Health check (no auth needed)
curl http://your-server:8000/health

# Authenticated request
curl -H "Authorization: Bearer $SSH_KEY" http://your-server:8000/overwatch/system

# Get service status
curl -H "Authorization: Bearer $SSH_KEY" http://your-server:8000/overwatch/services
```

> Use `your-server:8000` — **not** `localhost:8000` unless you are on the machine itself. SSH (port 22) is closed; this API is your remote access path.

## API Endpoints

### Health Check
- `GET /health` - Basic API health check (no authentication required)

### Overwatch Monitoring
- `GET /overwatch/system` - Complete system health metrics (CPU, memory, disk, network)
- `GET /overwatch/services` - Status of all monitored services

### Endpoint Management
- `GET /endpoints` - List all available endpoints (currently localhost only)
- `GET /endpoints/{endpoint_id}/health` - Health data for specific endpoint

### Service Status
- `GET /hardn/status` - HARDN service status
- `GET /legion/status` - Legion daemon status

### Diagnostics
- `GET /diagnostics/full` - Full system diagnostics and information

## Usage for Remote Servers

> Reminder: SSH (port 22) is closed. Use port **8000** for API access and port **9002** for Grafana.

### Monitoring from a Remote Machine

```bash
# Check system health
curl -H "Authorization: Bearer YOUR_SSH_PUBLIC_KEY" http://your-server:8000/overwatch/system

# Get service status
curl -H "Authorization: Bearer YOUR_SSH_PUBLIC_KEY" http://your-server:8000/overwatch/services

# Monitor specific endpoint
curl -H "Authorization: Bearer YOUR_SSH_PUBLIC_KEY" http://your-server:8000/endpoints/localhost/health
```

### Python Integration

```python
import requests

# Use your SSH public key as the API key
SSH_PUBLIC_KEY = "ssh-rsa API KEY HERE..."  # Your full public key
BASE_URL = "http://your-server:8000"

headers = {"Authorization": f"Bearer {SSH_PUBLIC_KEY}"}

# Get system health
response = requests.get(f"{BASE_URL}/overwatch/system", headers=headers)
health_data = response.json()

# Check if services are running
response = requests.get(f"{BASE_URL}/overwatch/services", headers=headers)
services = response.json()
```

## Usage for Local Admins

### Local System Monitoring

```bash
# Quick health check (no auth required)
curl http://localhost:8000/health

# Full system diagnostics
curl -H "Authorization: Bearer YOUR_SSH_PUBLIC_KEY" http://localhost:8000/diagnostics/full | jq

# Check all services
curl -H "Authorization: Bearer YOUR_SSH_PUBLIC_KEY" http://localhost:8000/overwatch/services | jq '.services'

# Monitor CPU/memory usage
curl -H "Authorization: Bearer YOUR_SSH_PUBLIC_KEY" http://localhost:8000/overwatch/system | jq '.system_health.cpu_percent, .system_health.memory.percent'
```

### Service Management

```bash
# Check HARDN service status
curl -H "Authorization: Bearer YOUR_SSH_PUBLIC_KEY" http://localhost:8000/hardn/status

# Check Legion daemon status
curl -H "Authorization: Bearer YOUR_SSH_PUBLIC_KEY" http://localhost:8000/legion/status

# Execute HARDN command (limited commands only)
curl -X POST -H "Authorization: Bearer YOUR_SSH_PUBLIC_KEY" \
  -H "Content-Type: application/json" \
  -d '{"command": "status"}' \
  http://localhost:8000/hardn/execute
```

### Interactive API Documentation

Access the interactive API documentation at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Response Examples

### System Health Response
```json
{
  "endpoint_id": "server-name",
  "system_health": {
    "cpu_percent": 13.0,
    "memory": {
      "total": 17179869184,
      "available": 14343278592,
      "percent": 16.4
    },
    "disk": {
      "total": 1000204886016,
      "free": 838414909440,
      "percent": 16.1
    },
    "network": {
      "connections": 45,
      "bytes_sent": 1523456789,
      "bytes_recv": 2345678901
    },
    "load_average": [0.5, 0.3, 0.2],
    "uptime": 70788.83,
    "timestamp": "2025-09-24T18:11:19.498045"
  },
  "services": {
    "hardn": {
      "service": "hardn.service",
      "active": true,
      "status": "active",
      "details": {
        "activestate": "active",
        "substate": "running",
        "description": "HARDN Security Service"
      },
      "timestamp": "2025-09-24T18:11:19.498045"
    }
  },
  "timestamp": "2025-09-24T18:11:19.498045"
}
```

### Services Status Response
```json
{
  "endpoint_id": "server-name",
  "services": {
    "hardn.service": {
      "service": "hardn.service",
      "active": true,
      "status": "active",
      "details": {
        "activestate": "active",
        "substate": "running"
      },
      "timestamp": "2025-09-24T18:11:19.676798"
    },
    "legion-daemon.service": {
      "service": "legion-daemon.service",
      "active": true,
      "status": "active",
      "timestamp": "2025-09-24T18:11:19.676798"
    }
  },
  "timestamp": "2025-09-24T18:11:19.676798"
}
```

### LEGION Scan Response
```json
{
  "command": "sudo hardn legion",
  "return_code": 0,
  "stdout": "LEGION security scan completed successfully...",
  "stderr": "",
  "success": true,
  "timestamp": "2025-09-24T18:15:30.123456"
}
```

## Security Notes

- Always use HTTPS in production environments
- Rotate SSH keys regularly
- Implement rate limiting for production deployments
- Monitor API access logs for security incidents
- The `/health` endpoint is the only one that doesn't require authentication
