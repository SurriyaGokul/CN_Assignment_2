#!/usr/bin/env python3
"""
DNS Resolution from PCAP Files
Extracts domains from PCAP files and resolves them using the custom resolver

This script:
1. Parses PCAP files to extract DNS queries
2. Resolves each unique domain using the custom resolver
3. Measures and compares performance
4. Generates detailed reports and graphs
"""

import os
import sys
import time
import json
from collections import defaultdict
from datetime import datetime

# Import our modules
from parse_pcap import DNSPacketParser
from custom_resolver import DNSResolver


class PCAPResolverAnalyzer:
    """Analyze DNS resolution from PCAP files using custom resolver"""
    
    def __init__(self, pcap_dir='../data', output_dir='./logs'):
        """
        Initialize analyzer
        
        Args:
            pcap_dir (str): Directory containing PCAP files
            output_dir (str): Directory for output files
        """
        self.pcap_dir = pcap_dir
        self.output_dir = output_dir
        self.resolver = DNSResolver(log_file=f'{output_dir}/queries.log')
        self.results = []
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
    
    def extract_domains_from_pcap(self, pcap_file):
        """
        Extract unique domains from a PCAP file
        
        Args:
            pcap_file (str): Path to PCAP file
            
        Returns:
            list: List of (domain, qtype) tuples
        """
        print(f"\nExtracting domains from {os.path.basename(pcap_file)}...")
        
        parser = DNSPacketParser(pcap_file)
        queries, _ = parser.parse_all()
        
        # Extract unique domains
        domains = set()
        for query in queries:
            if query['queries']:
                for q in query['queries']:
                    domain = q['name'].rstrip('.')
                    qtype = q['type_name']
                    # Only process A and AAAA records for now
                    if qtype in ['A', 'AAAA']:
                        domains.add((domain, qtype))
        
        domains_list = sorted(list(domains))
        print(f"Found {len(domains_list)} unique domains")
        
        return domains_list
    
    def resolve_domains(self, domains, max_domains=None):
        """
        Resolve a list of domains using custom resolver
        
        Args:
            domains (list): List of (domain, qtype) tuples
            max_domains (int): Maximum number of domains to resolve (None = all)
            
        Returns:
            list: Resolution results
        """
        if max_domains:
            domains = domains[:max_domains]
        
        print(f"\nResolving {len(domains)} domains using custom resolver...")
        print("="*80)
        
        results = []
        
        for i, (domain, qtype) in enumerate(domains, 1):
            print(f"\n[{i}/{len(domains)}] Resolving: {domain} ({qtype})")
            
            start_time = time.time()
            
            try:
                result = self.resolver.resolve(domain, qtype, timeout=5)
                elapsed = time.time() - start_time
                
                if result and result.get('answers'):
                    print(f"  ✓ Success in {elapsed:.4f}s - {len(result['answers'])} answer(s)")
                    status = 'success'
                    answers = result['answers']
                    steps = result.get('steps', 0)
                else:
                    print(f"  ✗ Failed in {elapsed:.4f}s")
                    status = 'failed'
                    answers = []
                    steps = 0
                
                results.append({
                    'domain': domain,
                    'qtype': qtype,
                    'status': status,
                    'latency': elapsed,
                    'steps': steps,
                    'answers': answers,
                    'timestamp': datetime.now().isoformat()
                })
                
            except Exception as e:
                elapsed = time.time() - start_time
                print(f"  ✗ Error: {str(e)}")
                results.append({
                    'domain': domain,
                    'qtype': qtype,
                    'status': 'error',
                    'latency': elapsed,
                    'steps': 0,
                    'answers': [],
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
            
            # Small delay between queries to avoid overwhelming servers
            time.sleep(0.5)
        
        return results
    
    def analyze_pcap_file(self, pcap_file, max_domains=None):
        """
        Complete analysis of a single PCAP file
        
        Args:
            pcap_file (str): Path to PCAP file
            max_domains (int): Maximum domains to resolve (None = all)
            
        Returns:
            dict: Analysis results
        """
        print(f"\n{'='*80}")
        print(f"ANALYZING: {os.path.basename(pcap_file)}")
        print('='*80)
        
        # Extract domains
        domains = self.extract_domains_from_pcap(pcap_file)
        
        if not domains:
            print("No domains found in PCAP file")
            return None
        
        # Resolve domains
        results = self.resolve_domains(domains, max_domains)
        
        # Calculate statistics
        total = len(results)
        successful = sum(1 for r in results if r['status'] == 'success')
        failed = sum(1 for r in results if r['status'] in ['failed', 'error'])
        
        latencies = [r['latency'] for r in results if r['status'] == 'success']
        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        
        steps = [r['steps'] for r in results if r['status'] == 'success']
        avg_steps = sum(steps) / len(steps) if steps else 0
        
        throughput = total / sum(r['latency'] for r in results) if results else 0
        
        analysis = {
            'pcap_file': os.path.basename(pcap_file),
            'total_queries': total,
            'successful': successful,
            'failed': failed,
            'success_rate': (successful / total * 100) if total > 0 else 0,
            'avg_latency_ms': avg_latency * 1000,
            'min_latency_ms': min(latencies) * 1000 if latencies else 0,
            'max_latency_ms': max(latencies) * 1000 if latencies else 0,
            'avg_steps': avg_steps,
            'throughput_qps': throughput,
            'results': results
        }
        
        # Print summary
        print(f"\n{'='*80}")
        print(f"RESULTS FOR: {os.path.basename(pcap_file)}")
        print('='*80)
        print(f"Total queries: {total}")
        print(f"Successful: {successful}")
        print(f"Failed: {failed}")
        print(f"Success rate: {analysis['success_rate']:.2f}%")
        print(f"Average latency: {analysis['avg_latency_ms']:.2f} ms")
        print(f"Min latency: {analysis['min_latency_ms']:.2f} ms")
        print(f"Max latency: {analysis['max_latency_ms']:.2f} ms")
        print(f"Average steps: {analysis['avg_steps']:.2f}")
        print(f"Throughput: {analysis['throughput_qps']:.2f} queries/sec")
        print('='*80)
        
        return analysis
    
    def analyze_all_pcaps(self, max_domains_per_file=None):
        """
        Analyze all PCAP files in the directory
        
        Args:
            max_domains_per_file (int): Max domains per file (None = all)
            
        Returns:
            list: List of analysis results
        """
        # Find all PCAP files
        pcap_files = []
        for file in os.listdir(self.pcap_dir):
            if file.endswith('.pcap') and 'Zone.Identifier' not in file:
                pcap_files.append(os.path.join(self.pcap_dir, file))
        
        if not pcap_files:
            print(f"No PCAP files found in {self.pcap_dir}")
            return []
        
        pcap_files.sort()
        print(f"\nFound {len(pcap_files)} PCAP files to analyze")
        
        all_results = []
        
        for pcap_file in pcap_files:
            result = self.analyze_pcap_file(pcap_file, max_domains_per_file)
            if result:
                all_results.append(result)
        
        return all_results
    
    def export_results(self, results):
        """
        Export results to various formats
        
        Args:
            results (list): Analysis results
        """
        # Export to JSON
        json_file = os.path.join(self.output_dir, 'custom_dns_analysis.json')
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n✓ Results exported to {json_file}")
        
        # Export to CSV
        import csv
        csv_file = os.path.join(self.output_dir, 'custom_dns.csv')
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'PCAP File', 'Domain', 'Query Type', 'Status', 
                'Latency (ms)', 'Steps', 'Answers'
            ])
            
            for result in results:
                for query in result['results']:
                    writer.writerow([
                        result['pcap_file'],
                        query['domain'],
                        query['qtype'],
                        query['status'],
                        f"{query['latency'] * 1000:.2f}",
                        query['steps'],
                        '; '.join(query['answers']) if query['answers'] else ''
                    ])
        
        print(f"✓ Results exported to {csv_file}")
        
        # Export summary CSV
        summary_file = os.path.join(self.output_dir, 'custom_dns_summary.csv')
        with open(summary_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'PCAP File', 'Total Queries', 'Successful', 'Failed', 
                'Success Rate (%)', 'Avg Latency (ms)', 'Avg Steps', 'Throughput (qps)'
            ])
            
            for result in results:
                writer.writerow([
                    result['pcap_file'],
                    result['total_queries'],
                    result['successful'],
                    result['failed'],
                    f"{result['success_rate']:.2f}",
                    f"{result['avg_latency_ms']:.2f}",
                    f"{result['avg_steps']:.2f}",
                    f"{result['throughput_qps']:.2f}"
                ])
        
        print(f"✓ Summary exported to {summary_file}")
    
    def print_overall_summary(self, results):
        """Print overall summary across all PCAP files"""
        if not results:
            return
        
        total_queries = sum(r['total_queries'] for r in results)
        total_successful = sum(r['successful'] for r in results)
        total_failed = sum(r['failed'] for r in results)
        
        all_latencies = []
        all_steps = []
        for r in results:
            for q in r['results']:
                if q['status'] == 'success':
                    all_latencies.append(q['latency'] * 1000)
                    all_steps.append(q['steps'])
        
        avg_latency = sum(all_latencies) / len(all_latencies) if all_latencies else 0
        avg_steps = sum(all_steps) / len(all_steps) if all_steps else 0
        
        print(f"\n{'='*80}")
        print("OVERALL SUMMARY - CUSTOM DNS RESOLVER")
        print('='*80)
        print(f"Total PCAP files analyzed: {len(results)}")
        print(f"Total queries: {total_queries}")
        print(f"Total successful: {total_successful}")
        print(f"Total failed: {total_failed}")
        print(f"Overall success rate: {(total_successful/total_queries*100):.2f}%")
        print(f"Average latency: {avg_latency:.2f} ms")
        print(f"Average steps per query: {avg_steps:.2f}")
        print('='*80)


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='DNS Resolution from PCAP Files')
    parser.add_argument('--pcap-dir', default='../data', help='Directory containing PCAP files')
    parser.add_argument('--output-dir', default='./logs', help='Output directory for results')
    parser.add_argument('--max-domains', type=int, default=None, 
                       help='Maximum domains to resolve per PCAP file (default: all)')
    parser.add_argument('--single-pcap', help='Analyze a single PCAP file')
    
    args = parser.parse_args()
    
    print("="*80)
    print("DNS RESOLUTION FROM PCAP FILES")
    print("Custom Iterative Resolver")
    print("="*80)
    
    # Create analyzer
    analyzer = PCAPResolverAnalyzer(args.pcap_dir, args.output_dir)
    
    # Analyze PCAP files
    if args.single_pcap:
        # Analyze single file
        results = [analyzer.analyze_pcap_file(args.single_pcap, args.max_domains)]
    else:
        # Analyze all files
        results = analyzer.analyze_all_pcaps(args.max_domains)
    
    if results:
        # Export results
        analyzer.export_results(results)
        
        # Print overall summary
        analyzer.print_overall_summary(results)
        
        # Print resolver statistics
        analyzer.resolver.print_statistics()
        
        # Export resolver logs
        analyzer.resolver.export_logs_to_json(f'{args.output_dir}/query_logs.json')
        analyzer.resolver.export_logs_to_csv(f'{args.output_dir}/custom_dns_detailed.csv')
        
        print("\n✓ Analysis complete!")
        print(f"\nOutput files saved to: {args.output_dir}/")
        print("  - custom_dns_analysis.json (detailed results)")
        print("  - custom_dns.csv (all queries)")
        print("  - custom_dns_summary.csv (summary statistics)")
        print("  - custom_dns_detailed.csv (detailed query logs)")
        print("  - query_logs.json (JSON query logs)")
        print("  - queries.log (detailed text log)")
    else:
        print("\n✗ No results to export")


if __name__ == "__main__":
    main()
