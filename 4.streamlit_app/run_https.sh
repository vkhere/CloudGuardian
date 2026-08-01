#!/usr/bin/env bash
# run_https.sh - start the console over HTTPS (macOS / Linux equivalent of run_https.ps1)
set -e
PORT="${1:-8501}"
CERT="certs/cloudguardian.crt"
KEY="certs/cloudguardian.key"
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  echo "No certificate found. Generating..."
  python3 tools/make_certs.py
fi
echo "Starting HTTPS on https://console.cloudguardian.local:${PORT}"
python3 -m streamlit run app.py \
  --server.port "$PORT" \
  --server.address 0.0.0.0 \
  --server.sslCertFile "$CERT" \
  --server.sslKeyFile "$KEY"
