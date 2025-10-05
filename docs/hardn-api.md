# HARDN API

## Purpose

The HARDN API provides comprehensive overwatch and health monitoring for endpoints in distributed environments. It integrates with HARDN security services and the Legion monitoring daemon to enable real-time system monitoring, diagnostics, and management. This API facilitates secure access to endpoint health data, service status, and system metrics for administrators and automated monitoring systems.

This server does not replace the **Grafana** endpoint system or the **Wazuh** agent, but allows an Open Source tool for those intrested in hollistic monitoring within their own tool sets. 

## Authentication

All API requests require authentication using SSH key-based Bearer tokens. Generate an SSH key pair locally and use the public key value in the Authorization header.

### Generate SSH Key Pair

```bash
# Generate a new SSH key pair (RSA recommended for compatibility)
ssh-keygen -t rsa -b 4096 -C "hardn-api-key" -f ~/.ssh/hardn_api_key

# Or generate Ed25519 key (more secure, but check compatibility)
ssh-keygen -t ed25519 -C "hardn-api-key" -f ~/.ssh/hardn_api_key
```

**Note:** Store the private key securely and never share it.

### Extract Public Key for API Authentication

```bash
# Get the public key content (single line)
cat ~/.ssh/hardn_api_key.pub

# Example output: ssh-rsa <API KEY>... user@hostname
```

### Use Public Key in API Requests

Include the full public key content in the Authorization header:

```
Authorization: Bearer ssh-rsa <PUT YOUR API KEY HERE>...
```

**Note:** Use the complete public key string (starting with `ssh-rsa` or `ssh-ed25519`) as the Bearer token value.

### Example: Generate and Use SSH Key

```bash
# 1. Generate SSH key pair
ssh-keygen -t rsa -b 4096 -C "hardn-api-key" -f ~/.ssh/hardn_api_key

# 2. Extract public key for use in API calls
SSH_KEY=$(cat ~/.ssh/hardn_api_key.pub)
echo $SSH_KEY

# Example output: ssh-rsa <YOUR_API_KEY_HERE> hardn-test-key

# 3. Use in curl command
curl -H "Authorization: Bearer $SSH_KEY" http://localhost:8000/health
# Response: {"status":"healthy","service":"hardn-api","version":"1.0.0","timestamp":"2025-09-24T18:21:04.055365"}

# 4. Get system health data
curl -H "Authorization: Bearer $SSH_KEY" http://localhost:8000/overwatch/system | jq '.system_health.cpu_percent'
# Response: 9.5
```

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

### LEGION Operations
- `POST /legion/scan` - Run Legion security scan with options
- `POST /legion/baseline` - Create new Legion system baseline
- `GET /legion/logs` - Get recent Legion daemon logs

### Command Execution
- `POST /hardn/execute` - Execute limited HARDN commands (admin only)

### Diagnostics
- `GET /diagnostics/full` - Full system diagnostics and information

## Usage for Remote Servers

### Monitoring from Remote Server

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

### LEGION Operations

```bash
# Run Legion security scan
curl -X POST -H "Authorization: Bearer YOUR_SSH_PUBLIC_KEY" \
  -H "Content-Type: application/json" \
  -d '{"verbose": true, "json": true}' \
  http://localhost:8000/legion/scan

# Create Legion baseline
curl -X POST -H "Authorization: Bearer YOUR_SSH_PUBLIC_KEY" \
  http://localhost:8000/legion/baseline

# Get Legion logs
curl -H "Authorization: Bearer YOUR_SSH_PUBLIC_KEY" \
  "http://localhost:8000/legion/logs?lines=100"
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
