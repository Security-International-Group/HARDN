#!/bin/bash
# HARDN UFW Setup Script
HARDN_STATUS "Configuring firewall with strict rules..."

if command -v ufw >/dev/null 2>&1; then
    # Reset UFW to defaults
    ufw --force disable
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny routed
    
    # Allow SSH (rate limited)
    ufw limit ssh/tcp comment 'SSH rate limit'
   
    
    # Allow DNS
    ufw allow out 53 comment 'DNS'
    
    # Allow HTTP/HTTPS out
    ufw allow out 80/tcp comment 'HTTP'
    ufw allow out 443/tcp comment 'HTTPS'
    
    # Allow NTP
    ufw allow out 123/udp comment 'NTP'
    
    # Enable UFW
    ufw --force enable
    HARDN_STATUS "UFW firewall configured with strict rules"
fi