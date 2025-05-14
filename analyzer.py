import pandas as pd
import numpy as np # Retained for explicit dependency, though pandas uses it
import pyshark
import sys
import time
import argparse
import os

try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

def clear_console():
    """Clears the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

class NetworkTrafficAnalyzer:
    """
    Captures, parses, and analyzes network packets from a live interface or PCAP file.
    Uses Pandas for data processing and can optionally generate Matplotlib plots.
    """
    def __init__(self, interface=None, pcap_file=None, display_filter=None, plot_enabled=False, refresh_interval=None):
        """
        Initializes the analyzer.

        Args:
            interface (str, optional): Network interface for live capture.
            pcap_file (str, optional): Path to a PCAP file for analysis.
            display_filter (str, optional): Wireshark-style filter.
            plot_enabled (bool): If True, generate matplotlib plots.
            refresh_interval (int, optional): Console refresh interval (seconds) for live capture.
        """
        if not interface and not pcap_file:
            raise ValueError("Either a network interface or a PCAP file must be specified.")
        if interface and pcap_file:
            raise ValueError("Cannot specify both a network interface and a PCAP file simultaneously.")

        self.interface = interface
        self.pcap_file = pcap_file
        self.display_filter = display_filter
        self.plot_enabled = plot_enabled and MATPLOTLIB_AVAILABLE
        self.refresh_interval = refresh_interval
        
        self.collected_packets_data = []
        self.df_analysis = pd.DataFrame()
        self.last_refresh_time = 0

    def _get_packet_details(self, packet):
        """Extracts key details from a PyShark packet object."""
        try:
            details = {
                'Timestamp': packet.sniff_time.isoformat(),
                'Source MAC': getattr(packet.eth, 'src', 'N/A'),
                'Destination MAC': getattr(packet.eth, 'dst', 'N/A'),
                'EtherType': getattr(packet.eth, 'type', 'N/A'),
                'VLAN ID': getattr(packet.vlan, 'id', 'N/A') if hasattr(packet, 'vlan') else 'N/A',
                'Source IP': 'N/A',
                'Destination IP': 'N/A',
                'Protocol': 'N/A', # Higher-level protocol name (TCP, UDP, etc.)
                'Source Port': 'N/A',
                'Destination Port': 'N/A',
                'Packet Length': int(packet.length),
                'Highest Protocol': packet.highest_layer
            }

            if 'IP' in packet: # IPv4
                details['Source IP'] = packet.ip.src
                details['Destination IP'] = packet.ip.dst
                details['Protocol'] = packet.ip.proto # Protocol number
            elif 'IPV6' in packet:
                details['Source IP'] = packet.ipv6.src
                details['Destination IP'] = packet.ipv6.dst
                details['Protocol'] = packet.ipv6.nxt # Next Header (protocol number)
            elif 'ARP' in packet:
                details['Protocol'] = 'ARP'
                details['Source IP'] = packet.arp.src_proto_ipv4
                details['Destination IP'] = packet.arp.dst_proto_ipv4
                return details # ARP packets don't have transport layer ports

            # Map protocol numbers to names for TCP/UDP/ICMP if not already named 'ARP'
            # This part assumes IP layer was found.
            if 'TCP' in packet:
                details['Protocol'] = 'TCP' # Override protocol number with name
                details['Source Port'] = packet.tcp.srcport
                details['Destination Port'] = packet.tcp.dstport
            elif 'UDP' in packet:
                details['Protocol'] = 'UDP' # Override protocol number with name
                details['Source Port'] = packet.udp.srcport
                details['Destination Port'] = packet.udp.dstport
            elif 'ICMP' in packet:
                details['Protocol'] = 'ICMP' # Override protocol number with name
                details['ICMP Type'] = packet.icmp.type
                details['ICMP Code'] = packet.icmp.code
            
            # If protocol is still a number, try to map it (basic examples)
            # PyShark often sets packet.transport_layer correctly, but this is a fallback
            if isinstance(details['Protocol'], str) and details['Protocol'].isdigit():
                proto_map = {'6': 'TCP', '17': 'UDP', '1': 'ICMP'}
                details['Protocol'] = proto_map.get(details['Protocol'], f"Proto_{details['Protocol']}")

            return details
        except AttributeError:
            return None # Packet might be malformed or a type not fully handled
        except Exception as e:
            # print(f"Unexpected error processing packet: {e}") # Optional for debugging
            return None

    def _packet_handler_callback(self, packet):
        """Processes a single packet and optionally refreshes live display."""
        analyzed_packet = self._get_packet_details(packet)
        if analyzed_packet:
            self.collected_packets_data.append(analyzed_packet)

        if self.refresh_interval and self.interface: # Live capture with refresh
            current_time = time.time()
            if current_time - self.last_refresh_time >= self.refresh_interval:
                self.df_analysis = pd.DataFrame(self.collected_packets_data)
                clear_console()
                print(f"--- Live Traffic Update (Captured: {len(self.df_analysis)}) ---")
                self.display_analysis_summary(is_live_update=True)
                self.last_refresh_time = current_time
                print(f"\nCapturing on {self.interface}... Press Ctrl+C to stop.")

    def start_capture_and_analyze(self, packet_count=None, duration=None):
        """Starts packet capture (live or from file) and subsequent analysis."""
        self.collected_packets_data = [] # Reset for new capture/analysis
        self.last_refresh_time = time.time()

        capture_source_description = ""

        if self.pcap_file:
            capture_source_description = f"PCAP file: {self.pcap_file}"
            print(f"Reading from {capture_source_description}")
            if self.display_filter:
                 print(f"Using display filter: {self.display_filter}")
            capture = pyshark.FileCapture(
                input_file=self.pcap_file,
                display_filter=self.display_filter
            )
            try:
                print("Processing packets from file...")
                packet_num = 0
                for packet in capture:
                    self._packet_handler_callback(packet)
                    packet_num += 1
                    if packet_num % 1000 == 0: # Progress for large files
                        print(f"  Processed {packet_num} packets...")
                print(f"Finished processing {len(self.collected_packets_data)} packets from file.")
            except Exception as e:
                print(f"Error reading PCAP file: {e}")
                return
            finally:
                capture.close()

        elif self.interface:
            capture_source_description = f"interface: {self.interface}"
            print(f"Starting live capture on {capture_source_description}")
            if self.display_filter:
                print(f"Using display filter: {self.display_filter}")
            
            confirm = input(f"Capture on '{self.interface}' with filter '{self.display_filter or 'None'}'. Proceed? (y/N): ")
            if confirm.lower() != 'y':
                print("Capture aborted by user.")
                return

            capture = pyshark.LiveCapture(
                interface=self.interface,
                display_filter=self.display_filter
            )
            try:
                if self.refresh_interval and not duration and not packet_count:
                    print(f"Capturing continuously with {self.refresh_interval}s refresh. Press Ctrl+C to stop.")
                    capture.apply_on_packets(self._packet_handler_callback) # Indefinite
                elif duration:
                    print(f"Capturing for {duration} seconds...")
                    capture.apply_on_packets(self._packet_handler_callback, timeout=duration)
                    print(f"Finished capturing for {duration} seconds.")
                elif packet_count:
                    print(f"Capturing {packet_count} packets...")
                    processed_count = 0
                    for packet in capture.sniff_continuously(packet_count=packet_count):
                        self._packet_handler_callback(packet)
                        processed_count += 1
                        if processed_count % (packet_count // 10 or 1) == 0 and processed_count < packet_count:
                             print(f"  Processed {processed_count}/{packet_count} packets...")
                    print(f"Finished capturing {packet_count} packets.")
                else: # Default behavior if no count/duration/refresh for continuous
                    default_pk_count = 50
                    print(f"Capturing {default_pk_count} packets (default)...")
                    processed_count = 0
                    for packet in capture.sniff_continuously(packet_count=default_pk_count):
                        self._packet_handler_callback(packet)
                        processed_count +=1
                        if processed_count % (default_pk_count // 10 or 1) == 0 and processed_count < default_pk_count:
                             print(f"  Processed {processed_count}/{default_pk_count} packets...")
                    print(f"Finished capturing {default_pk_count} packets.")

            except PermissionError:
                print("Permission denied. Please run with administrator/root privileges.")
                sys.exit(1)
            except KeyboardInterrupt:
                print("\nCapture stopped by user (Ctrl+C).")
            except Exception as e:
                print(f"An error occurred during capture: {e}")
                if "No such device" in str(e) or "doesn't exist" in str(e):
                    print(f"Interface '{self.interface}' not found. Please check available interfaces.")
            finally:
                capture.close()
        
        if self.collected_packets_data:
            self.df_analysis = pd.DataFrame(self.collected_packets_data)
            # Avoid double printing final summary if live refresh was already showing it
            if not (self.refresh_interval and self.interface): 
                clear_console()
                print(f"\n--- Final Traffic Capture Summary (Source: {capture_source_description}) ---")
                print(f"Total packets captured/processed: {len(self.df_analysis)}")
                if not self.df_analysis.empty:
                    print("Sample of captured packets (first 5):")
                    print(self.df_analysis.head())
                else:
                    print("No processable packets were captured or data frame is empty.")
                self.display_analysis_summary() # Display final summary stats
        else:
            print("No data collected or processed.")


    def display_analysis_summary(self, is_live_update=False):
        """
        Displays a summary of the analyzed traffic, optionally with plots.

        Args:
            is_live_update (bool): True if this is a periodic update during live capture.
        """
        if self.df_analysis.empty:
            if not is_live_update: print("\nNo analysis to display: DataFrame is empty.")
            return

        if not is_live_update: print("\n--- Detailed Traffic Analysis ---")

        print("\n1. Protocol Distribution:")
        protocol_counts = self.df_analysis['Protocol'].value_counts()
        print(protocol_counts)
        if self.plot_enabled and not protocol_counts.empty and not is_live_update:
            plt.figure(figsize=(10, 6))
            protocol_counts.plot(kind='bar', color='skyblue')
            plt.title('Protocol Distribution')
            plt.xlabel('Protocol')
            plt.ylabel('Packet Count')
            plt.xticks(rotation=45, ha="right")
            plt.tight_layout()
            plt.show(block=False)

        print("\n2. Top Source IPs (Talkers):")
        top_src_ips = self.df_analysis['Source IP'].value_counts().nlargest(10)
        print(top_src_ips)
        if self.plot_enabled and not top_src_ips.empty and not is_live_update:
            plt.figure(figsize=(10, 6))
            top_src_ips.plot(kind='barh', color='lightcoral')
            plt.title('Top 10 Source IPs')
            plt.xlabel('Packet Count')
            plt.ylabel('Source IP')
            plt.gca().invert_yaxis() # Highest on top
            plt.tight_layout()
            plt.show(block=False)

        print("\n3. Top Destination IPs (Listeners):")
        top_dst_ips = self.df_analysis['Destination IP'].value_counts().nlargest(10)
        print(top_dst_ips)

        print("\n4. Top IP Flows (SrcIP:Port -> DstIP:Port [Proto]):")
        # Ensure ports are not 'N/A' for flow analysis
        flow_df = self.df_analysis[
            (self.df_analysis['Source Port'] != 'N/A') & 
            (self.df_analysis['Destination Port'] != 'N/A')
        ].copy() # Use .copy() to avoid SettingWithCopyWarning

        if not flow_df.empty:
            flow_df['Flow'] = flow_df.apply(
                lambda r: f"{r['Source IP']}:{r['Source Port']} -> {r['Destination IP']}:{r['Destination Port']} ({r['Protocol']})",
                axis=1
            )
            top_flows = flow_df['Flow'].value_counts().nlargest(10)
            print(top_flows)
        else:
            print("No TCP/UDP flows with port information to analyze.")
        
        print("\n5. Data Volume (Bytes) by Protocol:")
        self.df_analysis['Packet Length'] = pd.to_numeric(self.df_analysis['Packet Length'], errors='coerce')
        data_volume_protocol = self.df_analysis.groupby('Protocol')['Packet Length'].sum().sort_values(ascending=False)
        print(data_volume_protocol)

        print("\n6. Highest Layer Protocol Distribution:")
        highest_layer_counts = self.df_analysis['Highest Protocol'].value_counts().nlargest(10)
        print(highest_layer_counts)

        if self.plot_enabled and not is_live_update and MATPLOTLIB_AVAILABLE:
            print("\nMatplotlib plots are non-blocking. Close them manually or they will close on script exit.")

    def save_analysis_to_csv(self, filename="traffic_analysis_detailed.csv"):
        """Saves the analyzed packet data to a CSV file."""
        if not self.df_analysis.empty:
            print(f"\nSaving detailed analysis to {filename}...")
            try:
                self.df_analysis.to_csv(filename, index=False)
                print(f"Analysis saved to {filename}")
            except Exception as e:
                print(f"Error saving file: {e}")
        else:
            print("No data available to save.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Network Traffic Analyzer using PyShark and Pandas.",
        formatter_class=argparse.RawTextHelpFormatter, # For better help text formatting
        epilog="""Examples:
  Live capture 100 packets from eth0:
    sudo python %(prog)s -i eth0 -c 100
  Analyze a PCAP file with plots:
    python %(prog)s -f your_capture.pcap --plot
  Live capture for 30s with TCP filter, plots, and 5s refresh:
    sudo python %(prog)s -i eth0 -t 30 -F "tcp port 80" --plot --refresh 5
  Continuous live capture with 10s refresh (Ctrl+C to stop):
    sudo python %(prog)s -i eth0 --refresh 10
"""
    )
    # Input source group: either interface or pcap file, one is required
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("-i", "--interface", help="Network interface for live capture (e.g., eth0, en0, Wi-Fi).")
    source_group.add_argument("-f", "--pcapfile", help="PCAP file to read packets from.")

    # Capture options
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture (live capture).")
    parser.add_argument("-t", "--duration", type=int, help="Duration in seconds for live packet capture.")
    parser.add_argument("-F", "--filter", help="Wireshark display filter (e.g., 'tcp port 80', 'host 192.168.1.1').")
    
    # Output and display options
    parser.add_argument("--plot", action="store_true", help="Enable matplotlib plots for analysis summary.")
    parser.add_argument("--refresh", type=int, metavar="SECONDS",
                        help="Refresh interval (seconds) for live console updates during continuous or duration-based capture.")
    parser.add_argument("-o", "--output", default="traffic_analysis_detailed.csv",
                        help="Output CSV file name (default: traffic_analysis_detailed.csv).")

    args = parser.parse_args()

    if not MATPLOTLIB_AVAILABLE and args.plot:
        print("Warning: Matplotlib is not installed or could not be imported. Plotting will be disabled. "
              "Install with 'pip install matplotlib'.")

    # Warn about sudo for live capture on non-Windows systems
    if args.interface and (os.name != 'nt' and os.geteuid() != 0):
        print("Info: Live packet capture on non-Windows systems usually requires root/administrator privileges (e.g., run with 'sudo').")

    try:
        analyzer = NetworkTrafficAnalyzer(
            interface=args.interface,
            pcap_file=args.pcapfile,
            display_filter=args.filter,
            plot_enabled=args.plot,
            refresh_interval=args.refresh
        )

        analyzer.start_capture_and_analyze(packet_count=args.count, duration=args.duration)
        
        # The final summary display is now handled within start_capture_and_analyze
        # to avoid duplication if live refresh was active.

        if not analyzer.df_analysis.empty:
            analyzer.save_analysis_to_csv(args.output)

        if args.plot and MATPLOTLIB_AVAILABLE and not analyzer.df_analysis.empty:
            print("\nDisplaying plots. Close all plot windows to exit the script completely.")
            plt.show() # This will block until all plot windows are closed.

        print("\nNetwork traffic analysis complete.")

    except ValueError as ve: # Catch init errors
        print(f"Configuration Error: {ve}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)