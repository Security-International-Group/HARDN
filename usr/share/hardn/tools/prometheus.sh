#!/bin/bash
set -euo pipefail

# ------------------------------------------------------------
# Prometheus installation + scrape-config for HARDN
# ------------------------------------------------------------
# What this does:
#   - Installs prometheus + prometheus-node-exporter from Debian
#     (Prometheus is in main since Debian 12; no third-party repo needed)
#   - Writes a HARDN-specific scrape job pointed at the hardn-api
#     /metrics endpoint on $HARDN_API_PORT (default 8000)
#   - Opens UFW for $HARDN_PROMETHEUS_PORT (default 9090) when UFW is
#     active. Same allowlist story as Grafana: scope via
#     HARDN_PROMETHEUS_ALLOWED_CIDRS or leave open on a localhost-only host.
#   - Enables + restarts the service and runs a /-/ready probe
#
# Sources Prometheus reads off:
#   localhost:9100  prometheus-node-exporter (host CPU/mem/disk/network)
#   localhost:9090  prometheus itself (self-monitoring)
#   localhost:8000  hardn-api /metrics (HARDN service health, alerts,
#                                       SENTRY drift, cron job state)
#
# Designed to be:
#   - Idempotent (safe to run multiple times)
#   - Container-aware (skips daemon install in unprivileged containers
#     where the data dir cannot be persisted)
# ------------------------------------------------------------

source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

check_root
log_tool_execution "prometheus.sh"

hardn_detect_env

if hardn_in_container; then
    HARDN_STATUS "info" "Container detected (${HARDN_ENV_VIRT}); skipping Prometheus install (no persistent data dir)"
    exit 0
fi

PROM_PORT="${HARDN_PROMETHEUS_PORT:-9090}"
API_PORT="${HARDN_API_PORT:-8000}"
NODE_EXPORTER_PORT="${HARDN_NODE_EXPORTER_PORT:-9100}"
PROM_DROPIN="/etc/prometheus/prometheus.d/hardn-scrape.yml"

HARDN_STATUS "info" "Installing Prometheus + node exporter"
if ! install_package prometheus; then
    HARDN_STATUS "warning" "Prometheus package not available; skipping"
    exit 0
fi
install_package prometheus-node-exporter || \
    HARDN_STATUS "warning" "prometheus-node-exporter not installed; host metrics unavailable"

# ------------------------------------------------------------
# HARDN scrape config drop-in
#
# Debian's prometheus.deb expects a single /etc/prometheus/prometheus.yml
# and does NOT load drop-ins by default. We append a `scrape_config_files`
# directive to the main config that pulls in our drop-in directory, then
# write the drop-in there. This keeps HARDN edits separate from operator
# edits to the main file.
# ------------------------------------------------------------
PROM_CFG="/etc/prometheus/prometheus.yml"
if [ -f "$PROM_CFG" ]; then
    if ! grep -q 'scrape_config_files:' "$PROM_CFG" 2>/dev/null; then
        # Back up before appending
        cp "$PROM_CFG" "${PROM_CFG}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
        cat >> "$PROM_CFG" <<'EOF'

# HARDN-managed scrape configs (do not edit; see /etc/prometheus/prometheus.d/)
scrape_config_files:
  - /etc/prometheus/prometheus.d/*.yml
EOF
        HARDN_STATUS "info" "Appended scrape_config_files include to ${PROM_CFG}"
    fi
fi

install -d -o root -g root -m 0755 /etc/prometheus/prometheus.d

cat > "$PROM_DROPIN" <<EOF
# Managed by HARDN tools/prometheus.sh. Do not edit by hand.
scrape_configs:
  - job_name: hardn-api
    metrics_path: /metrics
    scheme: http
    static_configs:
      - targets: ['localhost:${API_PORT}']
        labels:
          source: hardn-api

  - job_name: node
    static_configs:
      - targets: ['localhost:${NODE_EXPORTER_PORT}']
        labels:
          source: node-exporter
EOF
chmod 0644 "$PROM_DROPIN"
HARDN_STATUS "info" "Wrote scrape config to ${PROM_DROPIN}"

# Reload service
if enable_service prometheus; then
    HARDN_STATUS "pass" "prometheus.service enabled"
fi
systemctl restart prometheus 2>/dev/null || \
    HARDN_STATUS "warning" "Could not restart prometheus.service"

# Health probe
if command -v curl >/dev/null 2>&1; then
    for i in 1 2 3 4 5; do
        code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${PROM_PORT}/-/ready" 2>/dev/null || true)
        if [ "$code" = "200" ]; then
            HARDN_STATUS "pass" "Prometheus is ready on port ${PROM_PORT}"
            break
        fi
        sleep 2
    done
fi

# UFW rule
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    if [ -n "${HARDN_PROMETHEUS_ALLOWED_CIDRS:-}" ]; then
        for cidr in ${HARDN_PROMETHEUS_ALLOWED_CIDRS}; do
            ufw allow proto tcp from "$cidr" to any port "$PROM_PORT" comment 'Prometheus (scoped)' >/dev/null 2>&1 || true
        done
        HARDN_STATUS "pass" "UFW rules added for Prometheus, scoped to: ${HARDN_PROMETHEUS_ALLOWED_CIDRS}"
    else
        ufw allow in "${PROM_PORT}/tcp" comment 'Prometheus dashboard' >/dev/null 2>&1 || true
        HARDN_STATUS "info" "UFW rule added: allow inbound port ${PROM_PORT}/tcp (Prometheus)"
        HARDN_STATUS "info" "Restrict with HARDN_PROMETHEUS_ALLOWED_CIDRS=10.0.0.0/8,..."
    fi
fi

HARDN_STATUS "info" "Prometheus setup complete"
HARDN_STATUS "info" "Access URL: http://localhost:${PROM_PORT}"
HARDN_STATUS "info" "HARDN metrics endpoint scraped: http://localhost:${API_PORT}/metrics"
