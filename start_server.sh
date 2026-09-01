#!/usr/bin/env sh
cd "$(dirname "$0")"
echo "SOC L1 Local Practice Lab: http://localhost:8000"
python3 -m http.server 8000
