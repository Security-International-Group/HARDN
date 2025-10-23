![HARDN Logo](assets/IMG_1233.jpeg)
# HARDN Audit Module Walkthrough

This guide explains how the OPENScap C-based audit engine under `src/audit/` works, how it uses generated rule metadata, and how to extend it. The walkthrough is organized around the three key inputs in that directory:

- `hardn_audit.c` – the executable audit engine.
- `rules_autogen.inc` – the generated rule registry consumed at build time.
- `rules_source.txt` – the human-readable source list that feeds code generation.

## High-Level Flow

```mermaid
detail
flowchart TD
    A[Start \`hardn_audit\`] --> B[Load RULES from \`rules_autogen.inc\`]
    B --> C[initialize_rule_overrides()]
    C --> D[patch_rule_check \u2192 replace placeholders]
    D --> E[UTC timestamp capture]
    E --> F[Iterate over every rule]
    F --> G{Has concrete check?}
    G -- yes --> H[Invoke rule-specific function]
    G -- no --> I[Fallback: check_not_implemented]
    H --> J[Return status + evidence]
    I --> J
    J --> K[json_escape_and_print()]
    K --> L[Emit JSON entry]
    L --> M[All rules processed]
    M --> N[Close JSON array and exit]
```

## File-by-File Breakdown

### `hardn_audit.c`

The core executable performs four responsibilities:

1. **Rule table bootstrap** – includes `rules_autogen.inc`, which expands to an array of `rule_definition_t` records via the `RULE_DEF` macro.
2. **Runtime overrides** – `initialize_rule_overrides()` remaps selected rules to concrete implementations. The default handler (`check_not_implemented`) keeps placeholder entries from blocking execution.
3. **Check execution** – each rule yields a `rule_result_t { status, evidence }`. Helper utilities load configuration files, parse PAM settings, verify UID/GID uniqueness, and format evidence.
4. **Reporting** – results are streamed as JSON with `status_to_string()` and `json_escape_and_print()` handling formatting and escaping.

Relevant helper structures:

- `rule_status_t` enumerates result states (pass, fail, not_applicable, error, not_implemented).
- `rule_definition_t` stores identifiers, titles, categories, severity, and a function pointer.
- Helper parsers (`load_file_lines`, `load_pwquality_config`, etc.) centralize repeated IO logic.

### `rules_autogen.inc`

This include file is generated from `rules_source.txt`. Each line expands via `RULE_DEF(...)`, populating the static `RULES` array. By default all checks use `check_not_implemented` until `initialize_rule_overrides()` swaps in bespoke functions.

When adding a new rule:

1. Append an entry to `rules_source.txt`.
2. Re-run the generation step (typically a build script) to refresh `rules_autogen.inc`.
3. Implement a concrete checker and call `patch_rule_check(<id>, <fn>)` inside `initialize_rule_overrides()`.

### `rules_source.txt`

`rules_source.txt` doubles as the canonical rule list and as documentation for compliance status. Each block provides a human-friendly title, the SCAP/XCCDF rule ID, and the latest evaluation result.

The generator pipeline reads this file and emits `rules_autogen.inc`, preserving ordering and categories. The `Result` column is informational—it does *not* change runtime behaviour—but it is useful when triaging which rules still lack implementations.

## Rule Lifecycle

1. **Definition** – rule metadata originates in `rules_source.txt`. The ID must match the Code Identifier expected by downstream tooling (SCAP profiles, dashboards, etc.).
2. **Generation** – a build helper turns the source list into `rules_autogen.inc` so the C compiler sees a compile-time array.
3. **Override** – `initialize_rule_overrides()` replaces the placeholder handler with a real function when one exists.
4. **Execution** – `main()` timestamps the run, loops over `RULES`, executes each check, and prints a JSON document such as:

   ```json
   {
     "report_version": "1.0",
     "generated_at": "2025-10-20T18:40:07Z",
     "rules": [
       {
         "id": "xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen",
         "title": "Ensure PAM Enforces Password Requirements - Minimum Length",
         "status": "pass",
         "evidence": "minlen=14",
         "category": "auth",
         "severity": "medium"
       }
     ]
   }
   ```

5. **Post-processing** – other HARDN components can ingest the JSON, render dashboards, or archive reports.

## Implemented Checks

The current overrides cover password policy and core account hygiene items:

- PAM pwquality parameters (`minlen`, `retry`, credits, `minclass`).
- Password hashing algorithm enforcement (`ENCRYPT_METHOD=SHA512`).
- Shadow password enforcement and UID/GID uniqueness.
- Shadow group hygiene.

Any rule not yet implemented returns `not_implemented` with evidence `"check not yet implemented"`, signalling feature debt without causing audit failures.

## Extending the Audit Engine

1. **Identify the rule** – add an entry to `rules_source.txt` (if missing) or reuse an existing one.
2. **Write the checker** – implement a function that returns `rule_result_t` and encapsulates file parsing or system calls. Keep helpers in `hardn_audit.c` when they can be reused across checks.
3. **Register the checker** – call `patch_rule_check("<rule_id>", my_checker)` inside `initialize_rule_overrides()`.
4. **Validate** – run the binary against a target system. Use evidence strings to surface the measurement to operators.

### Evidence Guidelines

- Keep evidence short and machine-readable (e.g., `"minlen=12 (expected >=14)"`).
- Prefer specific values over generic statements.
- Use `check_error()` to signal IO or parsing issues; it produces the `error` state.

## Troubleshooting

- **Missing evidence** – ensure helper functions populate `result.evidence` before returning.
- **Duplicate IDs** – generator scripts should guard against duplicates; if you see unexpected overrides, confirm the `RULE_DEF` order.
- **JSON formatting issues** – check for unescaped quotes in evidence strings; always pass them through `json_escape_and_print()`.

## Next Steps

- Expand coverage by porting additional rules from `rules_source.txt` into concrete checks.
- Consider splitting large helpers into dedicated translation units if the file grows substantially.
- Integrate unit or integration tests to exercise parsers against fixture files.
