# Design Architectures (Demo)

## LEGION
- the mermaid architecture of legion daemon, api, monitor and all services
- LEGION interacts with Linux backend services such as systemd for service lifecycle management (e.g., starting/stopping services), network manager for network configuration and monitoring, systemctl for system control commands, and other services like journald for logging, udev for device events, and cron for scheduled tasks. The Monitor Service captures metrics and events from these, while the LEGION API can issue commands or queries to them for automation and control.

```mermaid
graph TD
  %% ========= EXTERNAL CLIENTS =========
  U[Clients] -->|REST or gRPC| API[LEGION API Gateway]

  %% ========= CORE =========
  subgraph CORE[LEGION Core]
    direction TB
    D[LEGION Daemon]:::proc
    M[Monitor Service]:::proc
    WQ[Worker Queue]:::store
    DP[Data Processor]:::proc
    CFG[Config Loader]:::cfg
    SEC[Secrets and TLS]:::sec
    LOG[Logging Service]:::proc
    ALR[Alert Service]:::proc
    DB[(Operational DB)]:::store
    CCH[(Ephemeral Cache)]:::store

    API -->|authz RBAC| D
    API -->|enqueue jobs| WQ
    WQ -->|dispatch| DP
    D -->|load| CFG
    D -->|certs keys| SEC
    DP -->|persist| DB
    DP -->|cache| CCH
    M --> LOG
    M --> ALR
  end

  %% ========= LINUX BACKEND INTEGRATIONS =========
  subgraph LNX[Linux Backend Services]
    direction TB
    SYS[systemd]:::os
    NMM[NetworkManager]:::os
    SCT[systemctl CLI]:::os
    JRN[journald]:::os
    UDV[udev]:::os
    CRN[cron]:::os
  end

  %% ========= TELEMETRY PATHS =========
  M -. metrics events .-> SYS
  M -. link metrics .-> NMM
  M -. logs .-> JRN
  M -. device events .-> UDV
  M -. schedule results .-> CRN
  M -. command results .-> SCT

  %% ========= CONTROL PATHS =========
  API -->|start stop restart| SYS
  API -->|apply network cfg| NMM
  API -->|system control| SCT

  %% ========= ALERTS OUT =========
  ALR -->|notify| U

  classDef proc fill:#f8f9ff,stroke:#5b7fff,color:#173166;
  classDef store fill:#eef7ff,stroke:#2083c7,color:#0a3a55;
  classDef os fill:#fafafa,stroke:#9aa0a6,color:#333,stroke-dasharray:3 3;
  classDef sec fill:#fff5f5,stroke:#e53e3e,color:#7b1e1e;
  classDef cfg fill:#f7fee7,stroke:#65a30d,color:#2a3c09;
```

## HARDN
- the mermaid architecture of hardn. api. monitor and all services
- HARDN interacts with Linux backend services such as systemd for service lifecycle management (e.g., starting/stopping services), network manager for network configuration and monitoring, systemctl for system control commands, and other services like journald for logging, udev for device events, and cron for scheduled tasks. The Monitor Service captures metrics and events from these, while the HARDN API can issue commands or queries to them for automation and control.

```mermaid
graph TD
    A[Client] --> B[HARDN API]
    B --> C[Monitor Service]
    C --> D[Logging Service]
    C --> E[Alert Service]
    B --> F[Data Processor]
    F --> G[Database]
    F --> H[Cache]
    C --> I[systemd]
    C --> J[Network Manager]
    C --> K[systemctl]
    C --> L[Other Linux Services<br/>(e.g., journald, udev, cron)]
    B --> M[systemd Commands]
    B --> N[Network Manager Queries]
```

## HARDN Monitor
- the mermaid architecture of the HARDN Monitor detailing how it gathers data from in-cluster services and supplies read-only outputs to the GUI.
- HARDN Monitor aggregates operational data from HARDN Service, LEGION, HARDN API, and Grafana, normalizes it into read-only datasets, and exposes those to the GUI without any Prometheus integration.

```mermaid
graph TD
    A[HARDN Service] --> E[HARDN Monitor]
    B[LEGION] --> E
    C[HARDN API] --> E
    D[Grafana] --> E
    E --> F[Data Normalizer]
    F --> G[Read-Only Dataset]
    G --> H[HARDN GUI]
```

## Grafana
- the mermaid architecture of Grafana showing user access, data source proxying, dashboard rendering, and alert evaluation.
- Grafana authenticates users, retrieves data from monitored sources such as the HARDN Monitor and Logging Store, renders dashboards, and runs alert rules that publish notifications.

```mermaid
graph TD
    A[Users] --> B[Grafana UI]
    B --> C[Auth Service]
    B --> D[Dashboard Engine]
    D --> E[Data Source Proxy]
    E --> F[Time-Series DB]
    E --> G[Log Store]
    D --> H[Alert Rule Engine]
    H --> I[Notification Channels]
```
