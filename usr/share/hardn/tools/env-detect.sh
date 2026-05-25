#!/bin/bash
# HARDN environment detection
#
# Single source of truth for "where am I running?" — sourced by hardening
# modules and tools so they can gracefully skip steps that don't apply.
#
# After `hardn_detect_env` runs (or sourcing this file at top-level), the
# following variables are exported:
#
#   HARDN_ENV_VIRT          systemd-detect-virt output  (none|kvm|vmware|...|docker|lxc)
#   HARDN_ENV_IS_CONTAINER  1 if running inside a container, else 0
#   HARDN_ENV_IS_VM         1 if running inside a non-container VM, else 0
#   HARDN_ENV_IS_BAREMETAL  1 if neither container nor VM, else 0
#   HARDN_ENV_CLOUD         aws|gcp|azure|digitalocean|oracle|alibaba|none
#   HARDN_ENV_IS_CLOUD      1 if HARDN_ENV_CLOUD != none, else 0
#
# Detection is best-effort and cached after the first call.

HARDN_ENV_DETECTED="${HARDN_ENV_DETECTED:-0}"

# Pure-stdout detector for the virt type; returns "none" when no virt is detected
# or systemd-detect-virt is unavailable.
hardn_env_virt() {
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        systemd-detect-virt 2>/dev/null || printf 'none\n'
    else
        printf 'none\n'
    fi
}

# Cloud provider detection via DMI strings and well-known metadata files.
# Avoids hitting the network — only reads local files that are present at
# boot on every supported cloud image.
hardn_env_cloud() {
    local sys_vendor="" product_name="" bios_vendor=""
    [ -r /sys/class/dmi/id/sys_vendor ]  && sys_vendor=$(tr -d '\0' </sys/class/dmi/id/sys_vendor 2>/dev/null || true)
    [ -r /sys/class/dmi/id/product_name ] && product_name=$(tr -d '\0' </sys/class/dmi/id/product_name 2>/dev/null || true)
    [ -r /sys/class/dmi/id/bios_vendor ] && bios_vendor=$(tr -d '\0' </sys/class/dmi/id/bios_vendor 2>/dev/null || true)

    case "${sys_vendor}${product_name}${bios_vendor}" in
        *Amazon*|*amazon*|*EC2*)            printf 'aws\n';          return ;;
        *Google*|*GoogleCloud*)             printf 'gcp\n';          return ;;
        *Microsoft*|*Hyper-V*)
            # Microsoft DMI also covers on-prem Hyper-V; require Azure marker
            if [ -d /var/lib/waagent ] || [ -r /sys/class/dmi/id/chassis_asset_tag ] && \
               grep -qi '7783-7084-3265-9085-8269-3286-77' /sys/class/dmi/id/chassis_asset_tag 2>/dev/null; then
                printf 'azure\n'; return
            fi
            ;;
        *DigitalOcean*)                     printf 'digitalocean\n'; return ;;
        *Oracle*OCI*|*OracleCloud*)         printf 'oracle\n';       return ;;
        *Alibaba*|*AlibabaCloud*)           printf 'alibaba\n';      return ;;
    esac

    # cloud-init datasource hint (set by cloud-init at first boot)
    if [ -r /run/cloud-init/cloud-id ]; then
        local cid
        cid=$(tr -d '\0\n' </run/cloud-init/cloud-id 2>/dev/null || true)
        case "$cid" in
            aws)          printf 'aws\n';          return ;;
            gce|gcp)      printf 'gcp\n';          return ;;
            azure)        printf 'azure\n';        return ;;
            digitalocean) printf 'digitalocean\n'; return ;;
            oracle)       printf 'oracle\n';       return ;;
            aliyun|alibaba) printf 'alibaba\n';    return ;;
        esac
    fi

    printf 'none\n'
}

hardn_detect_env() {
    if [ "${HARDN_ENV_DETECTED}" = "1" ]; then
        return 0
    fi

    HARDN_ENV_VIRT="$(hardn_env_virt)"

    case "$HARDN_ENV_VIRT" in
        none)
            HARDN_ENV_IS_CONTAINER=0
            HARDN_ENV_IS_VM=0
            HARDN_ENV_IS_BAREMETAL=1
            ;;
        docker|lxc|lxc-libvirt|systemd-nspawn|podman|rkt|wsl|proot|openvz)
            HARDN_ENV_IS_CONTAINER=1
            HARDN_ENV_IS_VM=0
            HARDN_ENV_IS_BAREMETAL=0
            ;;
        *)
            HARDN_ENV_IS_CONTAINER=0
            HARDN_ENV_IS_VM=1
            HARDN_ENV_IS_BAREMETAL=0
            ;;
    esac

    # Belt-and-braces container check — systemd-detect-virt sometimes
    # reports the underlying hypervisor inside privileged containers.
    if [ -f /.dockerenv ] || [ -f /run/.containerenv ] || grep -qE '(docker|containerd|kubepods|lxc)' /proc/1/cgroup 2>/dev/null; then
        HARDN_ENV_IS_CONTAINER=1
        HARDN_ENV_IS_VM=0
        HARDN_ENV_IS_BAREMETAL=0
    fi

    HARDN_ENV_CLOUD="$(hardn_env_cloud)"
    if [ "$HARDN_ENV_CLOUD" = "none" ]; then
        HARDN_ENV_IS_CLOUD=0
    else
        HARDN_ENV_IS_CLOUD=1
    fi

    export HARDN_ENV_VIRT HARDN_ENV_CLOUD
    export HARDN_ENV_IS_CONTAINER HARDN_ENV_IS_VM HARDN_ENV_IS_BAREMETAL HARDN_ENV_IS_CLOUD
    HARDN_ENV_DETECTED=1
    export HARDN_ENV_DETECTED
}

# Convenience predicates — usage:
#   if hardn_in_container; then ...; fi
hardn_in_container() { hardn_detect_env; [ "$HARDN_ENV_IS_CONTAINER" = "1" ]; }
hardn_in_vm()        { hardn_detect_env; [ "$HARDN_ENV_IS_VM" = "1" ]; }
hardn_on_baremetal() { hardn_detect_env; [ "$HARDN_ENV_IS_BAREMETAL" = "1" ]; }
hardn_in_cloud()     { hardn_detect_env; [ "$HARDN_ENV_IS_CLOUD" = "1" ]; }

# Human-readable one-liner for logs.
hardn_env_summary() {
    hardn_detect_env
    local kind="baremetal"
    if [ "$HARDN_ENV_IS_CONTAINER" = "1" ]; then kind="container ($HARDN_ENV_VIRT)"
    elif [ "$HARDN_ENV_IS_VM" = "1" ];        then kind="vm ($HARDN_ENV_VIRT)"
    fi
    if [ "$HARDN_ENV_IS_CLOUD" = "1" ]; then
        printf '%s on %s\n' "$kind" "$HARDN_ENV_CLOUD"
    else
        printf '%s\n' "$kind"
    fi
}

# Cloud-provider metadata service CIDRs that HARDN must never block.
# Used by the firewall and fail2ban scripts.
hardn_cloud_metadata_cidrs() {
    hardn_detect_env
    # The IMDS endpoint is consistent across AWS, GCP, Azure (link-local).
    # Azure additionally uses 168.63.129.16 for DNS/agent telemetry.
    printf '169.254.169.254/32\n'
    if [ "$HARDN_ENV_CLOUD" = "azure" ]; then
        printf '168.63.129.16/32\n'
    fi
}

# Cloud load-balancer / health-check source CIDRs. Conservative defaults —
# operators override with $HARDN_CLOUD_LB_CIDRS in their environment.
# We do NOT auto-trust huge cloud-provider ranges here because that would
# silently widen the SSH/fail2ban allowlist; we ship only the safe link-local
# ranges and let the operator opt-in to wider trust.
hardn_cloud_health_check_cidrs() {
    hardn_detect_env
    if [ -n "${HARDN_CLOUD_LB_CIDRS:-}" ]; then
        printf '%s\n' ${HARDN_CLOUD_LB_CIDRS}
        return
    fi
    case "$HARDN_ENV_CLOUD" in
        gcp)
            # GCP health-check probers — published, stable ranges.
            printf '35.191.0.0/16\n'
            printf '130.211.0.0/22\n'
            ;;
        *) ;;
    esac
}

export -f hardn_env_virt
export -f hardn_env_cloud
export -f hardn_detect_env
export -f hardn_in_container
export -f hardn_in_vm
export -f hardn_on_baremetal
export -f hardn_in_cloud
export -f hardn_env_summary
export -f hardn_cloud_metadata_cidrs
export -f hardn_cloud_health_check_cidrs
