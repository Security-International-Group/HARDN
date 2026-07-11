# HARDN Console & API

The console is a loopback-only web UI backed by an axum REST API. It is started
with `hardn serve [port]` (default `8000`) and binds `127.0.0.1` only - it can
never be reached from another host.

## Running

```bash
hardn serve            # 127.0.0.1:8000
hardn serve 9000       # custom port
```

On start it prints two URLs, each carrying a one-time token:

```
HARDN console on http://127.0.0.1:8000  (loopback only; Ctrl-C to stop)
  operator: http://127.0.0.1:8000/?token=<operator-secret>
  viewer:   http://127.0.0.1:8000/?token=<viewer-secret>
```

Opening a `?token=` URL sets an `HttpOnly; SameSite=Strict` session cookie, then
the single-page console fetches the API authenticated for the rest of the
session.

### State directory

Secrets and the audit log live under the state directory, resolved in order:

1. `HARDN_STATE_DIR`
2. `XDG_DATA_HOME/hardn`
3. `~/.local/share/hardn`

Files created there (`operator.secret`, `viewer.secret`, `audit-log.jsonl`) are
mode `0600`. Packaging points `HARDN_STATE_DIR` at `/var/lib/hardn`.

### Report source

The console reads the audit report from `HARDN_REPORT_PATH` (default
`/var/log/hardn/hardn_audit_report.json`). If no report exists yet, a
representative sample is served so the console renders before the first scan.
`POST /api/v1/audit/run` executes the engine located via `HARDN_AUDIT_BIN` (or
`target/release/hardn-audit`, `/usr/lib/hardn/hardn-audit`).

## Authentication & roles

| Role | Reads | Mutations |
|------|-------|-----------|
| viewer | yes | no |
| operator | yes | yes |

Present the token as `Authorization: Bearer <token>` or the `hardn_session`
cookie. Unauthenticated requests to any `/api/v1` route (except `health`) return
`401`; viewer requests to a mutating route return `403`.

```bash
# obtain the tokens from `hardn serve` output, then:
curl -s -H "Authorization: Bearer $OP" http://127.0.0.1:8000/api/v1/compliance/summary
```

## Endpoints

### Reads (viewer or operator)

- `GET /api/v1/compliance/summary` - `{ total, pass, fail, na, error, score, grade }`
- `GET /api/v1/compliance/findings?result=&severity=` - `{ count, findings[] }`
- `GET /api/v1/system/telemetry` - `{ host, kernel, os, arch, fips }`
- `GET /api/v1/system/fips` - `{ enabled, source, note }`
- `GET /api/v1/hardening/controls` - `{ controls: [{ name, desc, state }] }`,
  probed live from the host
- `GET /api/v1/audit-log` - `{ entries[], integrity: { verified, count, head } }`
- `GET /api/v1/evidence/export?format=json|csv` - downloadable bundle; the JSON
  form carries `integrity: { algo: "sha256", hash }` over the payload

### Mutations (operator only)

- `POST /api/v1/audit/run` - runs the C audit engine, writes the report
- `POST /api/v1/hardening/apply/{id}` - records a control application (audit-logged)

### Unauthenticated

- `GET /api/v1/health` - liveness (no sensitive data)
- `GET /` - the console page

## Audit log integrity

The audit log is append-only JSONL. Each record chains to the previous one:

```
hash = SHA-256( prev | seq | ts | actor | action | detail )
```

`GET /api/v1/audit-log` recomputes the chain and returns
`integrity.verified = false` if any record was edited, reordered, or removed.
`integrity.head` is the current chain head; it is also included in exported
evidence bundles so an auditor can tie an export to a log state.

## Threat model

The console surface maps to the threats in [THREAT-MODEL.md](THREAT-MODEL.md):
network exposure (T1, loopback + CI gate), unauthenticated access (T2, token
gate), evidence tampering (T3, hash chain), and privilege escalation via
operator endpoints (T4, role gate + audit logging).
