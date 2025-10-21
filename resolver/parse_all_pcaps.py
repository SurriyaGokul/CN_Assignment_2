#!/usr/bin/env python3
"""
Batch PCAP Parser
Parses all PCAP files in the data directory
"""

import os
import sys
from parse_pcap import DNSPacketParser


def parse_all_pcaps(data_dir='../data', output_dir='./logs'):
    """
    Parse all PCAP files in the data directory
    
    Args:
        data_dir (str): Directory containing PCAP files
        output_dir (str): Directory to save output files
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # Find all PCAP files
    pcap_files = []
    for file in os.listdir(data_dir):
        if file.endswith('.pcap') and not file.endswith(':Zone.Identifier'):
            pcap_files.append(os.path.join(data_dir, file))
    
    if not pcap_files:
        print(f"No PCAP files found in {data_dir}")
        return
    
    pcap_files.sort()
    print(f"Found {len(pcap_files)} PCAP files to parse\n")
    
    # Parse each PCAP file
    all_statistics = {}
    
    for pcap_file in pcap_files:
        try:
            print(f"\n{'='*70}")
            print(f"Processing: {os.path.basename(pcap_file)}")
            print('='*70)
            
            # Parse the PCAP
            parser = DNSPacketParser(pcap_file)
            parser.parse_all()
            parser.print_summary()
            
            # Save statistics
            base_name = os.path.basename(pcap_file).replace('.pcap', '')
            all_statistics[base_name] = parser.get_statistics()
            
            # Export to JSON and CSV
            json_output = os.path.join(output_dir, f"{base_name}_parsed.json")
            csv_output = os.path.join(output_dir, f"{base_name}_parsed.csv")
            
            parser.export_to_json(json_output)
            parser.export_to_csv(csv_output)
            
            print(f"✓ Successfully parsed {os.path.basename(pcap_file)}")
            
        except Exception as e:
            print(f"✗ Error parsing {os.path.basename(pcap_file)}: {e}")
            import traceback
            traceback.print_exc()
    
    # Print overall summary
    print("\n" + "="*70)
    print("OVERALL SUMMARY")
    print("="*70)
    
    total_queries = 0
    total_responses = 0
    total_dns_packets = 0
    
    for pcap_name, stats in all_statistics.items():
        print(f"\n{pcap_name}:")
        print(f"  Total packets: {stats.get('total_packets', 0)}")
        print(f"  DNS packets: {stats.get('dns_packets', 0)}")
        print(f"  Queries: {stats.get('queries', 0)}")
        print(f"  Responses: {stats.get('responses', 0)}")
        
        total_queries += stats.get('queries', 0)
        total_responses += stats.get('responses', 0)
        total_dns_packets += stats.get('dns_packets', 0)
    
    print("\n" + "-"*70)
    print(f"Total DNS packets across all files: {total_dns_packets}")
    print(f"Total queries: {total_queries}")
    print(f"Total responses: {total_responses}")
    print("="*70)
    
    print(f"\n✓ All output files saved to: {output_dir}")


if __name__ == "__main__":
    # Allow custom data and output directories
    data_dir = sys.argv[1] if len(sys.argv) > 1 else '../data'
    output_dir = sys.argv[2] if len(sys.argv) > 2 else './logs'
    
    print("Batch PCAP Parser")
    print(f"Data directory: {data_dir}")
    print(f"Output directory: {output_dir}")
    
    parse_all_pcaps(data_dir, output_dir)
