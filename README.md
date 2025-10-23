# ubupcaps
Capture the network trafic and transform into dataset using Nfstream

# Real-Time Network Traffic Capture (JSONB + Wireshark)

Docker-first, real-time network traffic capture using NFStream with optional Wireshark/tshark integration. Flows are stored in JSONB (one-record-per-line) for fast ingestion/indexing. Optional raw PCAP files are preserved for forensic analysis.

- Main script: [network_capture_jsonb.py](network_capture_jsonb.py)
- Compose: [docker-compose.yml](docker-compose.yml)
- Dockerfile: [Dockerfile](Dockerfile)
- Convenience script: [run_wireshark_capture.sh](run_wireshark_capture.sh)

## Features

- NFStream flow capture with sub-second batch writes
- Optional Wireshark/tshark capture for network-wide visibility
- JSONB line-delimited output for easy indexing
- Optional raw PCAP saving with rotation
- Dockerized, auto-start on container run

## Quick Start

- Start (detached):
  ```bash
  docker compose up -d --build
  ```
- Tail logs:
  ```bash
  docker compose logs -f network-capture
  ```
- Stop:
  ```bash
  docker compose down
  ```

The container runs privileged with host networking for packet capture and writes to ./output in your repo.

## Configuration (env vars)

Set in [docker-compose.yml](docker-compose.yml):

- NETWORK_INTERFACE: interface to capture (e.g., eth0, wlan0)
- OUTPUT_FILE: JSONB output path (e.g., /app/output/traffic_flows.jsonb)
- BATCH_SIZE: flows per batch write (default: 100)
- VERBOSE: true/false for debug logging
- PCAP_FILE: optional path to process an existing PCAP instead of live capture
- USE_WIRESHARK: true/false to enable tshark
- CAPTURE_MODE: interface or network
- WIRESHARK_FILTER: tshark capture filter (e.g., not arp and not icmp)
- SAVE_PCAP: true/false to save raw PCAPs
- PCAP_ROTATION_SIZE: size in MB before starting a new PCAP (default: 100)
- PCAP_RETENTION_COUNT: retention count (legacy; all PCAPs are preserved in current build)

See usage in [network_capture_jsonb.py](network_capture_jsonb.py) and examples in [PCAP_SAVING.md](PCAP_SAVING.md).

## Outputs

- JSONB flows file: configured via OUTPUT_FILE (default under ./output)
- Optional PCAPs: ./output/pcaps/capture_YYYYMMDD_HHMMSS_NNNN.pcap

Example JSONB record format is documented in this README and implemented by [`NetworkCapture._write_flows_to_jsonb`](network_capture_jsonb.py).

## Run without compose (optional)

```bash
docker build -t network-capture .
docker run --privileged --network host \
  -v "$PWD/output:/app/output" \
  -e NETWORK_INTERFACE=wlp1s0 \
  -e USE_WIRESHARK=true \
  -e CAPTURE_MODE=network \
  -e SAVE_PCAP=true \
  network-capture
```

## Ignore output directory in Git

Add/ensure the following in .gitignore to exclude runtime data (requested):

```gitignore
/output
/output/*
!/output/.gitkeep
```

## Troubleshooting

- Permissions: container runs privileged; ensure the host user can read ./output. The script fixes file ownership when possible.
- tshark not found: image installs tshark; if using a custom base image, ensure apt-get install tshark.
- No flows: verify NETWORK_INTERFACE and that traffic is present; try removing WIRESHARK_FILTER.

## Files

- [network_capture_jsonb.py](network_capture_jsonb.py) — main capture entrypoint (auto-starts via Docker CMD)
- [docker-compose.yml](docker-compose.yml) — deployment and configuration
- [Dockerfile](Dockerfile) — Python 3.10 + NFStream + tshark
- [PCAP_SAVING.md](PCAP_SAVING.md) — PCAP preservation and analysis tips
- [run_wireshark_capture.sh](run_wireshark_capture.sh) — full rebuild and launch helper
