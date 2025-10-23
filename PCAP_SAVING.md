# PCAP File Preservation Feature

## Overview

The network capture system now supports saving raw PCAP files alongside the structured JSONB data. This provides the best of both worlds:

- **JSONB files**: Fast, indexed, searchable structured data for real-time analysis
- **PCAP files**: Raw packet data for forensic analysis, Wireshark inspection, and external tool integration

## Configuration

### Environment Variables

Add these environment variables to enable PCAP saving:

```bash
# Enable PCAP saving
SAVE_PCAP=true

# PCAP file rotation settings
PCAP_ROTATION_SIZE=100    # MB - rotate when file reaches this size
PCAP_RETENTION_COUNT=10   # Number of PCAP files to keep (oldest deleted)
```

### Docker Compose

The `docker-compose.yml` has been updated with PCAP saving enabled by default:

```yaml
environment:
  - SAVE_PCAP=true
  - PCAP_ROTATION_SIZE=100
  - PCAP_RETENTION_COUNT=10
```

## File Organization

When PCAP saving is enabled, files are organized as follows:

```
output/
├── traffic_flows.jsonb          # Structured flow data
└── pcaps/                       # Raw PCAP files
    ├── capture_20241231_143052_0001.pcap
    ├── capture_20241231_143152_0002.pcap
    └── capture_20241231_143252_0003.pcap
```

### PCAP File Naming

PCAP files use the format: `capture_YYYYMMDD_HHMMSS_NNNN.pcap`
- `YYYYMMDD`: Date (20241231)
- `HHMMSS`: Time (143052)
- `NNNN`: Sequential index (0001)

## Features

### 1. Automatic Rotation

- Files are automatically rotated when they reach the configured size (default: 100MB)
- New files are created seamlessly without interrupting capture
- Rotation ensures manageable file sizes for analysis tools

### 2. Retention Management

- Automatic cleanup of old PCAP files based on retention count
- Oldest files are removed when limit is exceeded
- Prevents unlimited disk usage growth

### 3. Real-time Access

- PCAP files are updated in real-time during capture
- Can be analyzed with external tools while capture is running
- Files are properly finalized when capture stops

## Usage Examples

### 1. List Available PCAP Files

```bash
python pcap_analysis_demo.py list
```

### 2. Analyze with Wireshark (GUI)

```bash
# Open latest PCAP in Wireshark
wireshark output/pcaps/capture_20241231_143052_0001.pcap
```

### 3. Command-line Analysis

```bash
# Protocol distribution
python pcap_analysis_demo.py protocols capture_20241231_143052_0001.pcap

# Top endpoints
python pcap_analysis_demo.py endpoints capture_20241231_143052_0001.pcap

# Suspicious traffic extraction
python pcap_analysis_demo.py suspicious capture_20241231_143052_0001.pcap
```

### 4. Advanced tshark Analysis

```bash
# Count packets by protocol
tshark -r output/pcaps/capture_20241231_143052_0001.pcap -q -z io,phs

# Extract HTTP traffic
tshark -r input.pcap -w http_traffic.pcap -Y "http"

# Find large transfers
tshark -r input.pcap -Y "tcp.len > 1400" -T fields -e ip.src -e ip.dst -e tcp.len
```

## Integration with External Tools

### Wireshark
- Direct GUI analysis of captured packets
- Deep packet inspection and protocol decoding
- Filter and search capabilities

### tshark
- Command-line packet analysis
- Scriptable batch processing
- Statistical analysis and reporting

### tcpdump
- Quick packet inspection
- Real-time monitoring of PCAP files
- Simple filtering and display

### Security Tools
- Import into SIEM systems
- Threat hunting platforms
- Network forensics tools
- IDS/IPS analysis

## Best Practices

### 1. Storage Management
- Monitor disk usage with large captures
- Consider external storage for long-term retention
- Implement backup strategies for critical captures

### 2. Performance Considerations
- PCAP saving adds slight overhead to capture
- Larger rotation sizes reduce file management overhead
- Balance retention count with available storage

### 3. Security
- PCAP files contain raw network data
- Implement appropriate access controls
- Consider encryption for sensitive environments

### 4. Analysis Workflow
- Use JSONB for real-time monitoring and alerting
- Use PCAP for deep forensic analysis and investigation
- Correlate findings between both data sources

## Troubleshooting

### PCAP Directory Not Created
- Check write permissions on output directory
- Verify SAVE_PCAP=true is set correctly

### Large File Sizes
- Reduce PCAP_ROTATION_SIZE if files are too large
- Implement more aggressive filtering with WIRESHARK_FILTER

### Performance Issues
- Monitor system resources during capture
- Consider disabling PCAP saving for high-volume environments
- Optimize disk I/O performance

## Technical Implementation

### Rotation Logic
1. Monitor temp PCAP file size during capture
2. When size exceeds threshold, finalize current file
3. Start new capture with fresh temp file
4. Clean up old files based on retention policy

### File Safety
- Temp files are used during active capture
- Files are atomically moved to final location
- Graceful handling of interruptions and shutdowns

### Integration Points
- PCAP saving integrates with existing Wireshark capture
- No impact on JSONB data collection
- Minimal performance overhead when enabled
