#!/bin/bash
set -e

# ============================================
# Sandbox Service Entrypoint
# ============================================

echo "========================================"
echo "  VulnScan Sandbox Service"
echo "========================================"

# Verify Docker socket access
if [ -S /var/run/docker.sock ]; then
    echo "[OK] Docker socket found"
    docker info > /dev/null 2>&1 && echo "[OK] Docker daemon accessible" || echo "[WARN] Docker daemon not accessible"
else
    echo "[WARN] Docker socket not mounted at /var/run/docker.sock"
fi

# Verify language runtimes
echo ""
echo "--- Language Runtimes ---"
python3 --version || true
node --version || true
java -version 2>&1 | head -n 1 || true
go version || true
gcc --version | head -n 1 || true

# Setup AppArmor profiles if available
if command -v apparmor_parser &> /dev/null; then
    echo ""
    echo "--- AppArmor Status ---"
    aa-status --enabled 2>/dev/null && echo "[OK] AppArmor enabled" || echo "[INFO] AppArmor not enforcing"
fi

# Setup seccomp
if [ -f "${SANDBOX_HOME}/seccomp-profile.json" ]; then
    echo ""
    echo "[OK] Seccomp profile loaded"
fi

# Ensure working directories exist
mkdir -p /tmp/sandbox/jobs /tmp/sandbox/containers /tmp/sandbox/logs
chmod 755 /tmp/sandbox
chmod 700 /tmp/sandbox/jobs /tmp/sandbox/containers

echo ""
echo "========================================"
echo "  Starting Sandbox API Server..."
echo "========================================"

exec "$@"
