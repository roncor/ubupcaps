#!/bin/bash

# Complete Docker cleanup and run Wireshark-enhanced JSONB capture

echo "=== Cleaning up Docker (containers, images, cache) ==="
docker compose down
docker container prune -f
docker image prune -a -f
docker system prune -a -f
docker builder prune -a -f

echo "=== Building new image with Wireshark support ==="
docker compose build --no-cache

echo "=== Starting Wireshark-enhanced network capture ==="
docker compose up -d

echo "=== Monitoring logs ==="
docker compose logs -f network-capture
