#!/bin/bash
source "$(cd "$(dirname "$0")" && pwd)/functions.sh"

HARDN_STATUS "info" "Ensuring Grafana package is installed"
if install_package grafana; then
    HARDN_STATUS "pass" "Grafana package present"
else
    HARDN_STATUS "error" "Grafana is not yet installed"
    apt install -y grafana || exit 1
    HARDN_STATUS "pass" "Grafana package installed" || exit 1
fi

HARDN_STATUS "info" "Enabling and starting Grafana service"
if enable_service grafana; then
    HARDN_STATUS "pass" "Grafana service enabled and running"
else
    HARDN_STATUS "warning" "Unable to enable or start Grafana service"
fi  

HARDN_STATUS "info" "Grafana setup complete"
