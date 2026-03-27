from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import logging
import os
import secrets
import subprocess
import time
from datetime import datetime
from typing import Dict, Optional

import psutil

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Authorized keys file for SSH public key auth
AUTHORIZED_KEYS_FILE = os.environ.get("HARDN_AUTHORIZED_KEYS", "/etc/hardn/authorized_keys")

app = FastAPI(
    title="HARDN API",
    description="HARDN API for overwatch and health monitoring of endpoints",
    version="1.0.0-1",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — restrict to explicit list; override via HARDN_API_CORS_ORIGINS (comma-separated)
_raw_origins = os.environ.get("HARDN_API_CORS_ORIGINS", "http://localhost:9002,http://127.0.0.1:9002")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# Security
security = HTTPBearer()


# SSH Public Key validation
def is_valid_ssh_public_key(key: str) -> bool:
    """Validate SSH public key format"""
    if not key or not isinstance(key, str):
        return False

    # SSH public keys start with specific prefixes
    valid_prefixes = [
        "ssh-rsa",
        "ssh-ed25519",
        "ssh-dss",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    ]

    return (
        any(key.startswith(prefix) for prefix in valid_prefixes)
        and len(key.split()) >= 2
    )


def verify_ssh_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify SSH public key against /etc/hardn/authorized_keys"""
    key = credentials.credentials
    if not is_valid_ssh_public_key(key):
        raise HTTPException(status_code=401, detail="Invalid SSH public key format")

    if not os.path.isfile(AUTHORIZED_KEYS_FILE):
        logger.error("Authorized keys file not found: %s", AUTHORIZED_KEYS_FILE)
        raise HTTPException(status_code=503, detail="Authorization unavailable — keys file missing")

    # Extract the key material (type + base64 blob, ignore optional comment)
    key_parts = key.split()
    if len(key_parts) < 2:
        raise HTTPException(status_code=401, detail="Malformed key")
    key_token = " ".join(key_parts[:2])

    try:
        with open(AUTHORIZED_KEYS_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                line_parts = line.split()
                if len(line_parts) >= 2:
                    line_token = " ".join(line_parts[:2])
                    if secrets.compare_digest(key_token, line_token):
                        return key
    except OSError as exc:
        logger.error("Cannot read authorized keys: %s", exc)
        raise HTTPException(status_code=503, detail="Authorization unavailable")

    raise HTTPException(status_code=401, detail="SSH public key not authorized")


def _safe_net_connections() -> Optional[int]:
    """Return active connection count, or None if permission is denied (non-root)."""
    try:
        return len(psutil.net_connections())
    except psutil.AccessDenied:
        logger.warning("psutil.net_connections() requires root; reporting None")
        return None


# System monitoring functions
def get_system_health() -> Dict:
    """Get comprehensive system health metrics"""
    try:
        return {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory": {
                "total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available,
                "percent": psutil.virtual_memory().percent,
            },
            "disk": {
                "total": psutil.disk_usage("/").total,
                "free": psutil.disk_usage("/").free,
                "percent": psutil.disk_usage("/").percent,
            },
            "network": {
                "connections": _safe_net_connections(),
                "bytes_sent": psutil.net_io_counters().bytes_sent,
                "bytes_recv": psutil.net_io_counters().bytes_recv,
            },
            "load_average": os.getloadavg() if hasattr(os, "getloadavg") else None,
            "uptime": time.time() - psutil.boot_time(),
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logger.error("Error getting system health: %s", e)
        return {"error": "System health unavailable"}


def get_service_status(service_name: str) -> Dict:
    """Get status of a systemd service"""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service_name],
            capture_output=True,
            text=True,
            timeout=5,
        )
        is_active = result.returncode == 0
        status = result.stdout.strip()

        # Get more details
        result_detail = subprocess.run(
            [
                "systemctl",
                "show",
                service_name,
                "--property=ActiveState,SubState,Description",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )

        details = {}
        if result_detail.returncode == 0:
            for line in result_detail.stdout.strip().split("\n"):
                if "=" in line:
                    key, value = line.split("=", 1)
                    details[key.lower()] = value

        return {
            "service": service_name,
            "active": is_active,
            "status": status,
            "details": details,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        return {
            "service": service_name,
            "error": str(e),
            "timestamp": datetime.now().isoformat(),
        }


def run_hardn_command(command: str) -> Dict:
    """Execute HARDN CLI commands"""
    try:
        # Run the hardn command with sudo; requires a sudoers entry for the hardn user:
        #   hardn ALL=(root) NOPASSWD: /usr/bin/hardn
        result = subprocess.run(
            ["sudo", "hardn", command], capture_output=True, text=True, timeout=30
        )

        return {
            "command": f"sudo hardn {command}",
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0,
            "timestamp": datetime.now().isoformat(),
        }
    except subprocess.TimeoutExpired:
        return {
            "command": f"sudo hardn {command}",
            "error": "Command timed out",
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logger.error("run_hardn_command failed: %s", e)
        return {
            "command": f"sudo hardn {command}",
            "error": "Command execution failed",
            "timestamp": datetime.now().isoformat(),
        }


# API Endpoints


@app.get("/health")
def health_check():
    """Basic health check endpoint"""
    return {
        "status": "healthy",
        "service": "hardn-api",
        "version": "1.0.0-1",
        "timestamp": datetime.now().isoformat(),
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
            "hardn_api": get_service_status("hardn-api.service"),
        },
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/overwatch/services")
def get_services_overwatch(api_key: str = Depends(verify_ssh_key)):
    """Get status of all HARDN-related services"""
    services = [
        "hardn.service",
        "legion-daemon.service",
        "hardn-api.service",
        "aide",
        "rkhunter",
        "clamav-daemon",
        "fail2ban",
        "auditd",
    ]

    results = {}
    for service in services:
        results[service] = get_service_status(service)

    return {
        "endpoint_id": os.uname().nodename,
        "services": results,
        "timestamp": datetime.now().isoformat(),
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
            "api": get_service_status("hardn-api.service")["active"],
        },
        "timestamp": datetime.now().isoformat(),
    }


@app.post("/hardn/execute")
def execute_hardn_command(command: str, api_key: str = Depends(verify_ssh_key)):
    """Execute HARDN CLI commands remotely"""
    allowed_commands = [
        "status",
        "list-modules",
        "list-tools",
        "security-report",
        "legion",
    ]

    if command not in allowed_commands:
        raise HTTPException(status_code=403, detail="Command not allowed")

    result = run_hardn_command(command)
    if not result.get("success", False):
        raise HTTPException(
            status_code=500, detail=result.get("stderr", "Command failed")
        )

    return result


@app.get("/hardn/status")
def get_hardn_status(api_key: str = Depends(verify_ssh_key)):
    """Get HARDN service status"""
    return get_service_status("hardn.service")


@app.get("/legion/status")
def get_legion_status(api_key: str = Depends(verify_ssh_key)):
    """Get Legion daemon status"""
    return get_service_status("legion-daemon.service")


@app.post("/legion/scan")
def run_legion_scan(
    options: Optional[Dict[str, bool]] = None, api_key: str = Depends(verify_ssh_key)
):
    """Run Legion security scan with specified options"""
    if options is None:
        options = {}

    # Build command arguments with sudo
    cmd_args = ["sudo", "hardn", "legion"]

    if options.get("verbose", False):
        cmd_args.append("--verbose")
    if options.get("json", False):
        cmd_args.append("--json")
    if options.get("ml_enabled", False):
        cmd_args.append("--ml-enabled")
    if options.get("predictive", False):
        cmd_args.append("--predictive")
    if options.get("response_enabled", False):
        cmd_args.append("--response-enabled")

    try:
        result = subprocess.run(
            cmd_args, capture_output=True, text=True, timeout=300  # 5 minute timeout
        )

        return {
            "command": " ".join(cmd_args),
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0,
            "timestamp": datetime.now().isoformat(),
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Legion scan timed out")


@app.post("/legion/baseline")
def create_legion_baseline(api_key: str = Depends(verify_ssh_key)):
    """Create new Legion system baseline"""
    try:
        result = subprocess.run(
            ["sudo", "hardn", "legion", "--create-baseline"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        return {
            "command": "sudo hardn legion --create-baseline",
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0,
            "timestamp": datetime.now().isoformat(),
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Baseline creation timed out")


@app.get("/legion/logs")
def get_legion_logs(lines: int = 50, api_key: str = Depends(verify_ssh_key)):
    """Get recent Legion daemon logs"""
    lines = max(1, min(lines, 500))  # cap between 1 and 500
    try:
        result = subprocess.run(
            ["journalctl", "-u", "legion-daemon", "-n", str(lines), "--no-pager"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        return {
            "service": "legion-daemon",
            "lines": lines,
            "logs": result.stdout,
            "timestamp": datetime.now().isoformat(),
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Log retrieval timed out")


@app.get("/diagnostics/full")
def get_full_diagnostics(api_key: str = Depends(verify_ssh_key)):
    """Get comprehensive system diagnostics"""
    return {
        "endpoint_id": os.uname().nodename,
        "system_info": {
            "hostname": os.uname().nodename,
            "kernel": os.uname().release,
            "architecture": os.uname().machine,
            "uptime": time.time() - psutil.boot_time(),
        },
        "health_metrics": get_system_health(),
        "services": {
            "hardn": get_service_status("hardn.service"),
            "legion": get_service_status("legion-daemon.service"),
            "hardn_api": get_service_status("hardn-api.service"),
        },
        "hardn_status": run_hardn_command("status"),
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/endpoints")
def list_endpoints(api_key: str = Depends(verify_ssh_key)):
    """List available endpoints (currently just localhost)"""
    return {
        "endpoints": [
            {
                "id": os.uname().nodename,
                "hostname": os.uname().nodename,
                "type": "localhost",
                "status": "active",
                "last_seen": datetime.now().isoformat(),
            }
        ],
        "total": 1,
    }


if __name__ == "__main__":
    import uvicorn

    api_host = os.environ.get("HARDN_API_HOST", "0.0.0.0")
    api_port = int(os.environ.get("HARDN_API_PORT", "8000"))

    print(f"Starting HARDN API server on http://{api_host}:{api_port}")
    print("Remote access: Grafana (port 9002) and HARDN API (port 8000) only. SSH port 22 is closed.")
    print(f"Auth: SSH public key required — add keys to {AUTHORIZED_KEYS_FILE}")
    print("API endpoints:")
    print("  GET /health - Health check")
    print("  GET /overwatch/system - System overwatch data")
    print("  GET /overwatch/services - Services status")
    print("  GET /endpoints/{id}/health - Endpoint health")
    print("  POST /hardn/execute - Execute HARDN commands")
    print("  GET /legion/status - Legion daemon status")
    print("  POST /legion/scan - Run Legion security scan")
    print("  POST /legion/baseline - Create Legion baseline")
    print("  GET /legion/logs - Get Legion daemon logs")
    print("  GET /diagnostics/full - Full system diagnostics")
    print("  GET /docs - API documentation")
    uvicorn.run(app, host=api_host, port=api_port)
