#!/usr/bin/env python3

"""
Network Traffic Capture Script with JSONB File Storage + Wireshark Integration
Automatically captures network traffic using NFStream and stores it as JSONB format in files.
Enhanced with Wireshark/tshark for broader network capture capabilities.
Designed for Docker with Python 3.10 - starts capturing immediately when run.
Optimized JSONB format for efficient indexing and querying.

Configuration via environment variables:
- NETWORK_INTERFACE: Network interface to capture from (default: eth0)
- OUTPUT_FILE: Output JSONB file path (default: /app/output/traffic.jsonb)
- BATCH_SIZE: Number of flows per batch (default: 100)
- PCAP_FILE: PCAP file to process instead of live capture (optional)
- USE_WIRESHARK: Enable Wireshark/tshark integration (true/false, default: false)
- WIRESHARK_FILTER: Wireshark capture filter (optional, e.g., "not arp and not icmp")
- CAPTURE_MODE: "interface" (local) or "network" (broader network monitoring)
- SAVE_PCAP: Save raw PCAP files alongside JSONB (true/false, default: false)
- PCAP_ROTATION_SIZE: PCAP file size in MB before rotation (default: 100)
- PCAP_RETENTION_COUNT: Number of PCAP files to keep (default: 10)
"""

import os
import sys
import json
import time
import logging
import signal
import subprocess
import tempfile
import shutil
import glob
from datetime import datetime
from typing import Dict, List, Any, Optional

import numpy as np
import pandas as pd
from nfstream import NFStreamer

# Simple logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

class NetworkCapture:
    """Network traffic capture that stores results in JSONB file format for efficient indexing."""
    
    def __init__(self, source: str, output_file: str, batch_size: int = 100, 
                 use_wireshark: bool = False, wireshark_filter: str = None, 
                 capture_mode: str = "interface", save_pcap: bool = False,
                 pcap_rotation_size: int = 100, pcap_retention_count: int = 10):
        self.source = source
        self.output_file = output_file
        self.batch_size = batch_size
        self.use_wireshark = use_wireshark
        self.wireshark_filter = wireshark_filter
        self.capture_mode = capture_mode
        self.save_pcap = save_pcap
        self.pcap_rotation_size = pcap_rotation_size  # MB
        self.pcap_retention_count = pcap_retention_count
        self.flows_buffer: List[Dict[str, Any]] = []
        self.total_flows = 0
        self.start_time = None
        self.running = True
        self.temp_pcap = None
        self.tshark_process = None
        self.current_pcap_file = None
        self.pcap_file_index = 0
        
        # Setup PCAP directory if saving PCAPs
        if self.save_pcap:
            self.pcap_dir = os.path.join(os.path.dirname(self.output_file), 'pcaps')
            os.makedirs(self.pcap_dir, exist_ok=True)
            logger.info(f"PCAP files will be saved to: {self.pcap_dir}")
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum}. Initiating graceful shutdown...")
        self.running = False
        if self.tshark_process:
            self.tshark_process.terminate()
        # Save any final PCAP data if enabled
        if self.save_pcap and self.temp_pcap:
            self._finalize_pcap_file()
    
    def _get_next_pcap_filename(self) -> str:
        """Generate next PCAP filename with timestamp and rotation."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.pcap_file_index += 1
        return os.path.join(self.pcap_dir, f"capture_{timestamp}_{self.pcap_file_index:04d}.pcap")
    
    def _rotate_pcap_files(self):
        """Implement PCAP file rotation and retention policy."""
        if not self.save_pcap:
            return
            
        # Get list of existing PCAP files
        pcap_pattern = os.path.join(self.pcap_dir, "capture_*.pcap")
        existing_pcaps = sorted(glob.glob(pcap_pattern))
        
        # Remove old files if we exceed retention count
        while len(existing_pcaps) >= self.pcap_retention_count:
            old_file = existing_pcaps.pop(0)
            try:
                os.remove(old_file)
                logger.info(f"Removed old PCAP file: {os.path.basename(old_file)}")
            except Exception as e:
                logger.warning(f"Failed to remove old PCAP file {old_file}: {e}")
    
    def _finalize_pcap_file(self):
        """Finalize current PCAP file by copying temp file to permanent location."""
        if not self.save_pcap or not self.temp_pcap or not os.path.exists(self.temp_pcap):
            return
            
        try:
            # Check if temp PCAP has data
            if os.path.getsize(self.temp_pcap) <= 24:  # Just PCAP header
                logger.debug("Temp PCAP file has no packet data, skipping save")
                return
            
            # Create final PCAP filename
            if not self.current_pcap_file:
                self.current_pcap_file = self._get_next_pcap_filename()
            
            # Copy temp PCAP to final location
            shutil.copy2(self.temp_pcap, self.current_pcap_file)
            file_size_mb = os.path.getsize(self.current_pcap_file) / (1024 * 1024)
            logger.info(f"Saved PCAP file: {os.path.basename(self.current_pcap_file)} ({file_size_mb:.2f} MB)")
            
            # Reset for next file
            self.current_pcap_file = None
            
            # Implement rotation
            self._rotate_pcap_files()
            
        except Exception as e:
            logger.error(f"Error finalizing PCAP file: {e}")
    
    def _check_pcap_rotation(self):
        """Check if current PCAP file needs rotation based on size."""
        if not self.save_pcap or not self.temp_pcap or not os.path.exists(self.temp_pcap):
            return
            
        try:
            file_size_mb = os.path.getsize(self.temp_pcap) / (1024 * 1024)
            if file_size_mb >= self.pcap_rotation_size:
                logger.info(f"PCAP file reached {file_size_mb:.2f}MB, rotating...")
                self._finalize_pcap_file()
                # Start new temp PCAP file
                if self.tshark_process:
                    self._restart_wireshark_capture()
        except Exception as e:
            logger.debug(f"Error checking PCAP rotation: {e}")
    
    def _restart_wireshark_capture(self):
        """Restart Wireshark capture with new temp file."""
        try:
            # Terminate existing process
            if self.tshark_process:
                self.tshark_process.terminate()
                try:
                    self.tshark_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.tshark_process.kill()
            
            # Setup new capture
            self._setup_wireshark_capture()
            logger.debug("Restarted Wireshark capture with new file")
            
        except Exception as e:
            logger.error(f"Error restarting Wireshark capture: {e}")
            self.running = False
    
    def _setup_wireshark_capture(self) -> str:
        """
        Setup Wireshark/tshark for network capture.
        Returns path to temporary PCAP file.
        """
        # Create temporary PCAP file
        fd, temp_pcap_path = tempfile.mkstemp(suffix='.pcap', prefix='capture_')
        os.close(fd)
        self.temp_pcap = temp_pcap_path
        
        # Build tshark command
        tshark_cmd = [
            'tshark',
            '-i', self.source,
            '-w', temp_pcap_path,
            '-F', 'pcap'
        ]
        
        # Add capture filter if specified
        if self.wireshark_filter:
            tshark_cmd.extend(['-f', self.wireshark_filter])
        
        # Network mode optimizations
        if self.capture_mode == "network":
            # Promiscuous mode for broader network capture
            tshark_cmd.extend(['-p'])  # Disable promiscuous mode (use -p to disable)
            logger.info("Network capture mode: Monitoring broader network traffic")
        else:
            logger.info("Interface capture mode: Monitoring local interface traffic")
        
        # Set buffer size for real-time capture
        tshark_cmd.extend(['-B', '64'])  # 64MB buffer
        
        logger.info(f"Starting tshark: {' '.join(tshark_cmd)}")
        
        # Start tshark process
        try:
            self.tshark_process = subprocess.Popen(
                tshark_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid  # Create new process group
            )
            
            # Wait a moment for tshark to start
            time.sleep(2)
            
            if self.tshark_process.poll() is not None:
                stderr = self.tshark_process.stderr.read().decode()
                raise RuntimeError(f"tshark failed to start: {stderr}")
            
            logger.info(f"Wireshark/tshark started successfully, writing to: {temp_pcap_path}")
            return temp_pcap_path
            
        except Exception as e:
            logger.error(f"Failed to start tshark: {e}")
            if os.path.exists(temp_pcap_path):
                os.unlink(temp_pcap_path)
            raise
    
    def _cleanup_wireshark(self):
        """Cleanup Wireshark/tshark process and temporary files."""
        # Finalize PCAP file if saving is enabled
        if self.save_pcap:
            self._finalize_pcap_file()
        
        if self.tshark_process:
            try:
                self.tshark_process.terminate()
                self.tshark_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.tshark_process.kill()
            except Exception as e:
                logger.warning(f"Error stopping tshark: {e}")
        
        # Only remove temp PCAP if not saving PCAPs
        if self.temp_pcap and os.path.exists(self.temp_pcap) and not self.save_pcap:
            try:
                os.unlink(self.temp_pcap)
                logger.info("Cleaned up temporary PCAP file")
            except Exception as e:
                logger.warning(f"Error cleaning up temp PCAP: {e}")
    
    
    def _flow_to_dict(self, flow) -> Dict[str, Any]:
        """
        Convert NFStream flow object to dictionary.
        
        Args:
            flow: NFStream flow object
            
        Returns:
            Dictionary representation of the flow
        """
        flow_dict = {}
        
        # Get all attributes from the flow object
        for attr in dir(flow):
            if not attr.startswith('_'):
                try:
                    value = getattr(flow, attr)
                    
                    # Skip methods and non-serializable objects
                    if callable(value):
                        continue
                    
                    # Handle different data types
                    if isinstance(value, (int, float, str, bool)):
                        flow_dict[attr] = value
                    elif isinstance(value, (list, tuple)):
                        # Convert to list and handle nested objects
                        flow_dict[attr] = list(value) if value else []
                    elif isinstance(value, np.ndarray):
                        flow_dict[attr] = value.tolist()
                    elif pd.isna(value) or value is None:
                        flow_dict[attr] = None
                    elif isinstance(value, (np.integer, np.floating)):
                        flow_dict[attr] = value.item()
                    else:
                        # Try to convert to string for other types
                        flow_dict[attr] = str(value)
                        
                except Exception as e:
                    logger.debug(f"Skipping attribute {attr}: {e}")
                    continue
        
        # Add timestamp
        flow_dict['capture_timestamp'] = datetime.now().isoformat()
        
        # Ensure we have basic flow identification
        if 'id' not in flow_dict or flow_dict['id'] is None:
            flow_dict['id'] = f"{flow_dict.get('src_ip', 'unknown')}:{flow_dict.get('src_port', 0)}>" \
                             f"{flow_dict.get('dst_ip', 'unknown')}:{flow_dict.get('dst_port', 0)}-" \
                             f"{flow_dict.get('protocol', 'unknown')}"
        
        return flow_dict
    
    def _sanitize_flows_data(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sanitize flows data to ensure JSON serialization compatibility.
        
        Args:
            flows: List of flow dictionaries
            
        Returns:
            Sanitized list of flow dictionaries
        """
        sanitized_flows = []
        
        for flow in flows:
            sanitized_flow = {}
            for key, value in flow.items():
                try:
                    # Handle numpy types and inf/nan values
                    if isinstance(value, (np.integer, np.floating)):
                        value = value.item()
                    elif isinstance(value, float):
                        if np.isnan(value) or np.isinf(value):
                            value = None
                    elif isinstance(value, np.ndarray):
                        value = value.tolist()
                    
                    sanitized_flow[key] = value
                except Exception as e:
                    logger.debug(f"Error sanitizing {key}: {e}")
                    sanitized_flow[key] = None
                    
            sanitized_flows.append(sanitized_flow)
        
        return sanitized_flows
    
    def _write_flows_to_jsonb(self, flows: List[Dict[str, Any]]):
        """
        Write flows to JSONB file format optimized for indexing.
        Uses compact JSON with one flow per line for efficient processing.
        
        Args:
            flows: List of flow dictionaries to write
        """
        if not flows:
            return
        
        try:
            # Sanitize data for JSON serialization
            sanitized_flows = self._sanitize_flows_data(flows)
            
            # Create JSONB format - each flow as a separate JSON object
            with open(self.output_file, 'a', encoding='utf-8') as f:
                for flow_data in sanitized_flows:
                    # Create optimized JSONB structure for indexing
                    jsonb_record = {
                        "timestamp": datetime.now().isoformat(),
                        "source": self.source,
                        "batch_id": f"batch_{int(time.time() * 1000)}",
                        "flow_id": self.total_flows - len(sanitized_flows) + sanitized_flows.index(flow_data) + 1,
                        # Core indexable fields at top level for fast access
                        "src_ip": flow_data.get('src_ip'),
                        "dst_ip": flow_data.get('dst_ip'),
                        "src_port": flow_data.get('src_port'),
                        "dst_port": flow_data.get('dst_port'),
                        "protocol": flow_data.get('protocol'),
                        "bidirectional_first_seen_ms": flow_data.get('bidirectional_first_seen_ms'),
                        "bidirectional_last_seen_ms": flow_data.get('bidirectional_last_seen_ms'),
                        "bidirectional_duration_ms": flow_data.get('bidirectional_duration_ms'),
                        "bidirectional_packets": flow_data.get('bidirectional_packets'),
                        "bidirectional_bytes": flow_data.get('bidirectional_bytes'),
                        # Complete flow data nested for detailed analysis
                        "flow_data": flow_data
                    }
                    
                    # Write as compact JSON (one line per record)
                    json_line = json.dumps(jsonb_record, ensure_ascii=False, separators=(',', ':'))
                    f.write(json_line + '\n')
            
            logger.info(f"Wrote {len(sanitized_flows)} flows to JSONB file: {self.output_file}")
            
        except Exception as e:
            logger.error(f"Error writing flows to JSONB file: {e}")
    
    def capture(self):
        """Main capture method with Wireshark integration support."""
        logger.info(f"Starting capture from: {self.source}")
        logger.info(f"Capture mode: {self.capture_mode}")
        logger.info(f"Using Wireshark: {self.use_wireshark}")
        self.start_time = datetime.now()
        
        try:
            if self.use_wireshark:
                # Wireshark-enhanced capture
                self._wireshark_enhanced_capture()
            else:
                # Standard NFStream capture
                self._standard_nfstream_capture()
                
        finally:
            if self.use_wireshark:
                self._cleanup_wireshark()
    
    def _wireshark_enhanced_capture(self):
        """Capture using Wireshark/tshark for broader network monitoring."""
        logger.info("Starting Wireshark-enhanced capture...")
        
        # Start tshark capture
        temp_pcap = self._setup_wireshark_capture()
        
        # Wait for some initial data
        time.sleep(5)
        
        # Process captured data in real-time using NFStream
        try:
            while self.running:
                # Check if tshark is still running
                if self.tshark_process and self.tshark_process.poll() is not None:
                    logger.error("tshark process died unexpectedly")
                    break
                
                # Process accumulated PCAP data
                if os.path.exists(temp_pcap) and os.path.getsize(temp_pcap) > 24:  # PCAP header size
                    # Check for PCAP rotation if enabled
                    if self.save_pcap:
                        self._check_pcap_rotation()
                    
                    try:
                        # Create NFStreamer from current PCAP data
                        streamer = NFStreamer(
                            source=temp_pcap,
                            statistical_analysis=True,
                            n_dissections=0,      # Fast processing
                            performance_report=0
                        )
                        
                        # Process flows
                        new_flows = 0
                        for flow in streamer:
                            if not self.running:
                                break
                            
                            # Convert flow to dict and add Wireshark metadata
                            flow_dict = self._flow_to_dict(flow)
                            flow_dict['capture_method'] = 'wireshark'
                            flow_dict['capture_mode'] = self.capture_mode
                            if self.wireshark_filter:
                                flow_dict['wireshark_filter'] = self.wireshark_filter
                            
                            self.flows_buffer.append(flow_dict)
                            self.total_flows += 1
                            new_flows += 1
                            
                            # Write batch when full
                            if len(self.flows_buffer) >= self.batch_size:
                                start_write = time.time()
                                self._write_flows_to_jsonb(self.flows_buffer)
                                write_time = time.time() - start_write
                                self.flows_buffer.clear()
                                
                                # Real-time performance monitoring
                                flows_per_sec = self.batch_size / max(write_time, 0.001)
                                logger.info(f"Processed {self.total_flows} flows | Write time: {write_time:.3f}s | Rate: {flows_per_sec:.1f} flows/s")
                        
                        if new_flows > 0:
                            logger.debug(f"Processed {new_flows} new flows from Wireshark capture")
                    
                    except Exception as e:
                        logger.debug(f"Error processing PCAP data: {e}")
                
                # Wait before next processing cycle
                time.sleep(2)
            
            # Write remaining flows
            if self.flows_buffer:
                self._write_flows_to_jsonb(self.flows_buffer)
            
            logger.info(f"Wireshark capture completed. Total flows: {self.total_flows}")
            
        except Exception as e:
            logger.error(f"Error in Wireshark capture: {e}")
            if self.flows_buffer:
                self._write_flows_to_jsonb(self.flows_buffer)
    
    def _standard_nfstream_capture(self):
        """Standard NFStream capture method."""
        # Setup NFStreamer with optimized real-time settings
        is_file = os.path.isfile(self.source)
        if is_file:
            streamer = NFStreamer(source=self.source, statistical_analysis=True)
        else:
            # Real-time optimized settings
            streamer = NFStreamer(
                source=self.source, 
                statistical_analysis=True,
                idle_timeout=15,      # Faster flow completion detection (15s instead of 60s)
                active_timeout=120,   # Shorter max flow duration (2min instead of 5min)
                accounting_mode=1,    # Enable real-time accounting
                n_dissections=0,      # Disable deep packet inspection for speed
                performance_report=0   # Disable performance reporting for speed
            )
        
        try:
            for flow in streamer:
                if not self.running:
                    break
                
                # Convert flow to dict
                flow_dict = self._flow_to_dict(flow)
                flow_dict['capture_method'] = 'nfstream'
                flow_dict['capture_mode'] = self.capture_mode
                
                self.flows_buffer.append(flow_dict)
                self.total_flows += 1
                
                # Write batch when full
                if len(self.flows_buffer) >= self.batch_size:
                    start_write = time.time()
                    self._write_flows_to_jsonb(self.flows_buffer)
                    write_time = time.time() - start_write
                    self.flows_buffer.clear()
                    
                    # Real-time performance monitoring
                    flows_per_sec = self.batch_size / max(write_time, 0.001)
                    logger.info(f"Processed {self.total_flows} flows | Write time: {write_time:.3f}s | Rate: {flows_per_sec:.1f} flows/s")
            
            # Write remaining flows
            if self.flows_buffer:
                self._write_flows_to_jsonb(self.flows_buffer)
            
            logger.info(f"Standard capture completed. Total flows: {self.total_flows}")
            
        except KeyboardInterrupt:
            logger.info("Capture interrupted")
        finally:
            if self.flows_buffer:
                self._write_flows_to_jsonb(self.flows_buffer)

def main():
    """Main function - starts capture automatically with environment variables."""
    
    # Get configuration from environment variables
    network_interface = os.getenv('NETWORK_INTERFACE', 'wlp1s0')
    output_file = os.getenv('OUTPUT_FILE', '/app/output/traffic_flows.jsonb')
    batch_size = int(os.getenv('BATCH_SIZE', '100'))
    pcap_file = os.getenv('PCAP_FILE')  # Optional
    verbose = os.getenv('VERBOSE', 'true').lower() == 'true'
    
    # Wireshark integration settings
    use_wireshark = os.getenv('USE_WIRESHARK', 'false').lower() == 'true'
    wireshark_filter = os.getenv('WIRESHARK_FILTER')  # e.g., "not arp and not icmp"
    capture_mode = os.getenv('CAPTURE_MODE', 'interface')  # 'interface' or 'network'
    
    # PCAP saving settings
    save_pcap = os.getenv('SAVE_PCAP', 'false').lower() == 'true'
    pcap_rotation_size = int(os.getenv('PCAP_ROTATION_SIZE', '100'))
    pcap_retention_count = int(os.getenv('PCAP_RETENTION_COUNT', '10'))
    
    # Set logging level
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    logger.info("=== Network Traffic Capture with JSONB + Wireshark ===")
    logger.info(f"Network Interface: {network_interface}")
    logger.info(f"Output File: {output_file}")
    logger.info(f"Batch Size: {batch_size}")
    logger.info(f"Use Wireshark: {use_wireshark}")
    logger.info(f"Capture Mode: {capture_mode}")
    logger.info(f"Save PCAP: {save_pcap}")
    if save_pcap:
        logger.info(f"PCAP Rotation Size: {pcap_rotation_size}MB")
        logger.info(f"PCAP Retention: {pcap_retention_count} files")
    if wireshark_filter:
        logger.info(f"Wireshark Filter: {wireshark_filter}")
    if pcap_file:
        logger.info(f"PCAP File: {pcap_file}")
    logger.info("=========================================================")
    
    # Determine source (PCAP file or network interface)
    if pcap_file:
        if not os.path.isfile(pcap_file):
            logger.error(f"PCAP file not found: {pcap_file}")
            sys.exit(1)
        source = pcap_file
        logger.info(f"Processing PCAP file: {pcap_file}")
    else:
        source = network_interface
        if use_wireshark:
            logger.info(f"Starting Wireshark-enhanced capture from interface: {network_interface}")
        else:
            logger.info(f"Starting standard NFStream capture from interface: {network_interface}")
    
    # Create output directory
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Created output directory: {output_dir}")
    
    # Validate Wireshark availability if requested
    if use_wireshark:
        try:
            result = subprocess.run(['tshark', '--version'], 
                                 capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                raise FileNotFoundError("tshark not found")
            logger.info("Wireshark/tshark validation successful")
        except Exception as e:
            logger.error(f"Wireshark/tshark not available: {e}")
            logger.error("Install with: apt-get install tshark or disable USE_WIRESHARK")
            sys.exit(1)
    
    # Start capture
    try:
        capture = NetworkCapture(
            source=source, 
            output_file=output_file, 
            batch_size=batch_size,
            use_wireshark=use_wireshark,
            wireshark_filter=wireshark_filter,
            capture_mode=capture_mode,
            save_pcap=save_pcap,
            pcap_rotation_size=pcap_rotation_size,
            pcap_retention_count=pcap_retention_count
        )
        capture.capture()
    except Exception as e:
        logger.error(f"Capture failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
