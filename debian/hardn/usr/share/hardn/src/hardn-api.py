from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import subprocess
import json
import psutil
import os
import time
from datetime import datetime
from typing import Dict, List, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="HARDN API",
    description="HARDN API for overwatch and health monitoring of endpoints",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# SSH Public Key validation
def is_valid_ssh_public_key(key: str) -> bool:
    """Validate SSH public key format"""
    if not key or not isinstance(key, str):
        return False

    # SSH public keys start with specific prefixes
    valid_prefixes = ['ssh-rsa', 'ssh-ed25519', 'ssh-dss', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521']

    return any(key.startswith(prefix) for prefix in valid_prefixes) and len(key.split()) >= 2

def verify_ssh_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify SSH public key authentication"""
    if not is_valid_ssh_public_key(credentials.credentials):
        raise HTTPException(status_code=401, detail="Invalid SSH public key format")
    return credentials.credentials

# System monitoring functions
def get_system_health() -> Dict:
    """Get comprehensive system health metrics"""
    try:
        return {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory": {
                "total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available,
                "percent": psutil.virtual_memory().percent
            },
            "disk": {
                "total": psutil.disk_usage('/').total,
                "free": psutil.disk_usage('/').free,
                "percent": psutil.disk_usage('/').percent
            },
            "network": {
                "connections": len(psutil.net_connections()),
                "bytes_sent": psutil.net_io_counters().bytes_sent,
                "bytes_recv": psutil.net_io_counters().bytes_recv
            },
            "load_average": os.getloadavg() if hasattr(os, 'getloadavg') else None,
            "uptime": time.time() - psutil.boot_time(),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting system health: {e}")
        return {"error": str(e)}

def get_service_status(service_name: str) -> Dict:
    """Get status of a systemd service"""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service_name],
            capture_output=True, text=True, timeout=5
        )
        is_active = result.returncode == 0
        status = result.stdout.strip()

        # Get more details
        result_detail = subprocess.run(
            ["systemctl", "show", service_name, "--property=ActiveState,SubState,Description"],
            capture_output=True, text=True, timeout=5
        )

        details = {}
        if result_detail.returncode == 0:
            for line in result_detail.stdout.strip().split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    details[key.lower()] = value

        return {
            "service": service_name,
            "active": is_active,
            "status": status,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "service": service_name,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

def run_hardn_command(command: str) -> Dict:
    """Execute HARDN CLI commands"""
    try:
        # Run the hardn command
        result = subprocess.run(
            ["hardn", command],
            capture_output=True, text=True, timeout=30
        )

        return {
            "command": f"hardn {command}",
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0,
            "timestamp": datetime.now().isoformat()
        }
    except subprocess.TimeoutExpired:
        return {
            "command": f"hardn {command}",
            "error": "Command timed out",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "command": f"hardn {command}",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# API Endpoints

@app.get("/health")
def health_check():
    """Basic health check endpoint"""
    return {
        "status": "healthy",
        "service": "hardn-api",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/overwatch/system")
def get_system_overwatch(api_key: str = Depends(verify_ssh_key)):
    """Get comprehensive system overwatch data"""
    return {
        "endpoint_id": os.uname().nodename,
        "system_health": get_system_health(),
        "services": {
            "hardn": get_service_status("hardn.service"),
            "legion": get_service_status("legion-daemon.service"),
            "hardn_api": get_service_status("hardn-api.service")
        },
        "timestamp": datetime.now().isoformat()
    }

@app.get("/overwatch/services")
def get_services_overwatch(api_key: str = Depends(verify_ssh_key)):
    """Get status of all HARDN-related services"""
    services = ["hardn.service", "legion-daemon.service", "hardn-api.service",
                "aide", "rkhunter", "clamav-daemon", "fail2ban", "auditd"]

    results = {}
    for service in services:
        results[service] = get_service_status(service)

    return {
        "endpoint_id": os.uname().nodename,
        "services": results,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/endpoints/{endpoint_id}/health")
def get_endpoint_health(endpoint_id: str, api_key: str = Depends(verify_ssh_key)):
    """Get health data for a specific endpoint"""
    hostname = os.uname().nodename
    if endpoint_id != hostname and endpoint_id != "localhost":
        raise HTTPException(status_code=404, detail="Endpoint not found")

    return {
        "endpoint_id": endpoint_id,
        "hostname": hostname,
        "health": get_system_health(),
        "services_status": {
            "hardn": get_service_status("hardn.service")["active"],
            "legion": get_service_status("legion-daemon.service")["active"],
            "api": get_service_status("hardn-api.service")["active"]
        },
        "timestamp": datetime.now().isoformat()
    }

@app.post("/hardn/execute")
def execute_hardn_command(command: str, api_key: str = Depends(verify_ssh_key)):
    """Execute HARDN CLI commands remotely"""
    allowed_commands = ["status", "list-modules", "list-tools", "security-report"]

    if command not in allowed_commands:
        raise HTTPException(status_code=403, detail="Command not allowed")

    result = run_hardn_command(command)
    if not result.get("success", False):
        raise HTTPException(status_code=500, detail=result.get("stderr", "Command failed"))

    return result

@app.get("/hardn/status")
def get_hardn_status(api_key: str = Depends(verify_ssh_key)):
    """Get HARDN service status"""
    return get_service_status("hardn.service")

@app.get("/legion/status")
def get_legion_status(api_key: str = Depends(verify_ssh_key)):
    """Get Legion daemon status"""
    return get_service_status("legion-daemon.service")

@app.get("/diagnostics/full")
def get_full_diagnostics(api_key: str = Depends(verify_ssh_key)):
    """Get comprehensive system diagnostics"""
    return {
        "endpoint_id": os.uname().nodename,
        "system_info": {
            "hostname": os.uname().nodename,
            "kernel": os.uname().release,
            "architecture": os.uname().machine,
            "uptime": time.time() - psutil.boot_time()
        },
        "health_metrics": get_system_health(),
        "services": {
            "hardn": get_service_status("hardn.service"),
            "legion": get_service_status("legion-daemon.service"),
            "hardn_api": get_service_status("hardn-api.service")
        },
        "hardn_status": run_hardn_command("status"),
        "timestamp": datetime.now().isoformat()
    }

@app.get("/endpoints")
def list_endpoints(api_key: str = Depends(verify_ssh_key)):
    """List available endpoints (currently just localhost)"""
    return {
        "endpoints": [{
            "id": os.uname().nodename,
            "hostname": os.uname().nodename,
            "type": "localhost",
            "status": "active",
            "last_seen": datetime.now().isoformat()
        }],
        "total": 1
    }

if __name__ == "__main__":
    import uvicorn
    print("Starting HARDN API server on http://localhost:8000")
    print("API endpoints:")
    print("  GET /health - Health check")
    print("  GET /overwatch/system - System overwatch data")
    print("  GET /overwatch/services - Services status")
    print("  GET /endpoints/{id}/health - Endpoint health")
    print("  POST /hardn/execute - Execute HARDN commands")
    print("  GET /diagnostics/full - Full system diagnostics")
    print("  GET /docs - API documentation")
    print("")
    print("API Key required for most endpoints. Use: 'hardn-api-key-2024'")
    uvicorn.run(app, host="127.0.0.1", port=8000)