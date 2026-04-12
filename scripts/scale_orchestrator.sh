#!/bin/bash
# Phase 3: Production-Scale Orchestrator for SOFuzz
# Iterates over a directory of APKs and executes the deep native analysis automatically

if [ -z "$1" ]; then
    echo "Usage: ./scale_orchestrator.sh <apk_directory>"
    exit 1
fi

APK_DIR=$1
for apk in "$APK_DIR"/*.apk; do
    # Skip if wildcard didn't expand to a real file
    [ -e "$apk" ] || continue
    
    echo "=========================================================="
    echo "[*] Orchestrating Production-Scale analysis for: $apk"
    echo "=========================================================="
    source venv/bin/activate && sofuzz --apk "$apk" --analyze-only
    echo "[+] Completed $apk. Moving to next."
done
