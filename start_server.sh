#!/usr/bin/env sh
cd "$(dirname "$0")"
echo "SOC L1 Investigation Lab v3: http://localhost:8000"
python3 -m http.server 8000
