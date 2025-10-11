#!/bin/bash
# this banneer is sourced from the binary

set -euo pipefail
declare -a candidates=()

if [ $# -gt 0 ] && [ -n "$1" ]; then
    candidates+=("$1")
fi

for name in hardn hardn-xdr; do
    if command -v "$name" >/dev/null 2>&1; then
        candidates+=("$(command -v "$name")")
    fi
done

for bin in "${candidates[@]}"; do
    if [ -x "$bin" ]; then
        tmp_file=$(mktemp)
        if "$bin" --banner >"$tmp_file" 2>/dev/null; then
            cat "$tmp_file"
            rm -f "$tmp_file"
            exit 0
        fi
        rm -f "$tmp_file"
    fi
done

# Fallback ASCII banner (mirrors src/display/banner.rs)
cat <<'EOF'
   ▄█    █▄            ▄████████         ▄████████      ████████▄       ███▄▄▄▄
  ███    ███          ███    ███        ███    ███      ███   ▀███      ███▀▀▀██▄
  ███    ███          ███    ███        ███    ███      ███    ███      ███   ███
 ▄███▄▄▄▄███▄▄        ███    ███       ▄███▄▄▄▄██▀      ███    ███      ███   ███
▀▀███▀▀▀▀███▀       ▀███████████      ▀▀███▀▀▀▀▀        ███    ███      ███   ███
  ███    ███          ███    ███      ▀███████████      ███    ███      ███   ███
  ███    ███          ███    ███        ███    ███      ███   ▄███      ███   ███
  ███    █▀           ███    █▀         ███    ███      ████████▀        ▀█   █▀
                                        ███    ███

           E X T E N D E D + D E T E C T I O N + A N D + R E S P O N S E
        -------------------------------------------------------------------
            S E C U R I T Y -- I N T E R N A T I O N A L -- G R O U P
EOF
