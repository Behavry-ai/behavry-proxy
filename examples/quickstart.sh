#!/usr/bin/env bash
# Behavry Proxy — Quickstart
#
# First governed MCP tool call in <3 minutes.
#
# Prerequisites: Docker, Docker Compose
#
# Usage: ./examples/quickstart.sh

set -euo pipefail

echo "🛡️  Behavry Proxy — Quickstart"
echo ""

# Check prerequisites
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Install from https://docker.com"
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose not found. Install from https://docs.docker.com/compose/install/"
    exit 1
fi

# Create servers config if not exists
if [ ! -f config/servers.yaml ]; then
    echo "📝 Creating config/servers.yaml from example..."
    cp config/servers.yaml.example config/servers.yaml
fi

# Start services
echo "🚀 Starting Behavry Proxy + OPA..."
docker compose up -d

# Wait for health
echo "⏳ Waiting for proxy to be ready..."
for i in $(seq 1 30); do
    if curl -s http://localhost:8080/health | grep -q "healthy\|degraded"; then
        break
    fi
    sleep 1
done

echo ""
echo "✅ Behavry Proxy is running!"
echo ""
echo "   Proxy:   http://localhost:8080"
echo "   OPA:     http://localhost:8181"
echo "   Health:  http://localhost:8080/health"
echo "   Metrics: http://localhost:8080/metrics"
echo "   Servers: http://localhost:8080/servers"
echo ""
echo "📋 Example tool call:"
echo ""
echo '   curl -X POST http://localhost:8080/mcp/github \\'
echo '     -H "Content-Type: application/json" \\'
echo '     -H "X-Agent-Id: my-agent" \\'
echo '     -d '"'"'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_repos","arguments":{"org":"behavry"}}}'"'"''
echo ""
echo "📊 Terminal dashboard:"
echo "   python -m behavry_proxy.tui.dashboard"
echo ""
echo "🛑 Stop: docker compose down"
