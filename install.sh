#!/bin/bash
# 🐉 PacketWyrm Quick Install

echo "🐉 Installing PacketWyrm..."

# Check for root
[ "$EUID" -ne 0 ] && echo "❌ Run with sudo" && exit 1

# Install deps
apt update -qq
apt install -y -qq golang-go libpcap-dev docker.io docker-compose 2>/dev/null

# Build
cd "$(dirname "$0")"
cd backend && go mod tidy && go build -o packetwyrm

# Install command
ln -sf "$(pwd)/packetwyrm" /usr/local/bin/packetwyrm

echo "✅ Installed! Run: sudo packetwyrm"
