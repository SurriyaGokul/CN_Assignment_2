import socket
import struct
import time
import logging
import json
import os
from datetime import datetime
from collections import defaultdict
import threading
import dns.message
import dns.query
import dns.resolver
import dns.rdatatype
import dns.flags

class DNSResolver:
    """Custom DNS Resolver with Iterative Resolution"""
    
    ROOT_SERVERS = [
        '198.41.0.4',      # a.root-servers.net
        '199.9.14.201',    # b.root-servers.net
        '192.33.4.12',     # c.root-servers.net
        '199.7.91.13',     # d.root-servers.net
        '192.203.230.10',  # e.root-servers.net
        '192.5.5.241',     # f.root-servers.net
        '192.112.36.4',    # g.root-servers.net
        '198.97.190.53',   # h.root-servers.net
        '192.36.148.17',   # i.root-servers.net
        '192.58.128.30',   # j.root-servers.net
        '193.0.14.129',    # k.root-servers.net
        '199.7.83.42',     # l.root-servers.net
        '202.12.27.33',    # m.root-servers.net
    ]
    
    def __init__(self, log_file='logs/queries.log', recursive_mode=False):

        self.recursive_mode = recursive_mode
        self.log_file = log_file
        self.cache = {} # I gotta do later
        self.statistics = {
            'total_queries': 0,
            'successful': 0,
            'failed': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'total_latency': 0,
            'queries_by_type': defaultdict(int)
        }
        
        # Setup logging
        self._setup_logging()
        
        # Query logs for detailed analysis
        self.query_logs = []
        
    def _setup_logging(self):
        """Setup logging configuration"""
        # Create logs directory if it doesn't exist
        os.makedirs(os.path.dirname(self.log_file) if os.path.dirname(self.log_file) else 'logs', exist_ok=True)
        
        # Configure logger
        self.logger = logging.getLogger('DNSResolver')
        self.logger.setLevel(logging.DEBUG)
        
        # File handler
        fh = logging.FileHandler(self.log_file, mode='a')
        fh.setLevel(logging.DEBUG)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S.%f'
        )
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)
        
        self.logger.info("="*80)
        self.logger.info(f"DNS Resolver initialized - Mode: {'Recursive' if self.recursive_mode else 'Iterative'}")
        self.logger.info("="*80)
    
    def resolve(self, domain, qtype='A', timeout=5):
        """
        Main resolution function - performs iterative DNS resolution
        
        Args:
            domain (str): Domain name to resolve
            qtype (str): Query type (A, AAAA, MX, etc.)
            timeout (int): Timeout in seconds
            
        Returns:
            dict: Resolution result with answers and metadata
        """
        start_time = time.time()
        self.statistics['total_queries'] += 1
        self.statistics['queries_by_type'][qtype] += 1
        
        # Normalize domain
        if not domain.endswith('.'):
            domain = domain + '.'
        
        self.logger.info(f"\n{'='*80}")
        self.logger.info(f"NEW QUERY: {domain} (Type: {qtype})")
        self.logger.info(f"Mode: {'Recursive' if self.recursive_mode else 'Iterative'}")
        self.logger.info(f"{'='*80}")
        
        # Create query log entry
        query_log = {
            'timestamp': datetime.now().isoformat(),
            'domain': domain,
            'qtype': qtype,
            'mode': 'recursive' if self.recursive_mode else 'iterative',
            'steps': [],
            'total_time': 0,
            'cache_status': 'MISS',
            'success': False,
            'answers': [],
            'error': None
        }
        
        try:
            # Check cache (placeholder for Part F)
            cache_key = f"{domain}:{qtype}"
            if cache_key in self.cache:
                self.logger.info(f"CACHE HIT for {domain}")
                query_log['cache_status'] = 'HIT'
                self.statistics['cache_hits'] += 1
                # Would return cached result here
            else:
                self.statistics['cache_misses'] += 1
            
            # Perform iterative resolution
            result = self._iterative_resolve(domain, qtype, timeout, query_log)
            
            if result and result.get('answers'):
                self.statistics['successful'] += 1
                query_log['success'] = True
                query_log['answers'] = result['answers']
            else:
                self.statistics['failed'] += 1
                query_log['error'] = 'No answers found'
            
            total_time = time.time() - start_time
            query_log['total_time'] = total_time
            self.statistics['total_latency'] += total_time
            
            self.logger.info(f"RESOLUTION COMPLETE: {domain}")
            self.logger.info(f"Total time: {total_time:.4f} seconds")
            self.logger.info(f"Steps taken: {len(query_log['steps'])}")
            if result and result.get('answers'):
                self.logger.info(f"Answers found: {len(result['answers'])}")
                for answer in result['answers']:
                    self.logger.info(f"  -> {answer}")
            else:
                self.logger.info("No answers found")
            
            self.query_logs.append(query_log)
            
            return result
            
        except Exception as e:
            self.logger.error(f"ERROR resolving {domain}: {str(e)}")
            query_log['error'] = str(e)
            query_log['total_time'] = time.time() - start_time
            self.query_logs.append(query_log)
            self.statistics['failed'] += 1
            return None
    
    def _iterative_resolve(self, domain, qtype, timeout, query_log):
        """
        Perform iterative DNS resolution
        """
        current_servers = self.ROOT_SERVERS.copy()
        current_domain = domain
        step_number = 0
        
        while True:
            step_number += 1
            
            if step_number > 20:  # Prevent infinite loops
                self.logger.warning(f"Too many steps ({step_number}), aborting")
                return None
            
            # Try each server in the current list
            for server_ip in current_servers:
                try:
                    step_start = time.time()
                    
                    # Determine server type based on step
                    if step_number == 1 or current_servers == self.ROOT_SERVERS:
                        server_type = "ROOT"
                    else:
                        # Heuristic: if it's early in resolution, likely TLD
                        server_type = "TLD" if step_number <= 3 else "AUTHORITATIVE"
                    
                    self.logger.info(f"\nStep {step_number}: Querying {server_type} server: {server_ip}")
                    self.logger.info(f"  Query: {current_domain} (Type: {qtype})")
                    
                    # Create DNS query
                    query = dns.message.make_query(current_domain, qtype)
                    
                    # Try UDP first
                    try:
                        response = dns.query.udp(query, server_ip, timeout=timeout)
                    except Exception as udp_error:
                        self.logger.debug(f"  UDP failed, trying TCP: {udp_error}")
                        # Fall back to TCP
                        response = dns.query.tcp(query, server_ip, timeout=timeout)
                    
                    step_time = time.time() - step_start
                    
                    # Log the step
                    step_log = {
                        'step': step_number,
                        'server_type': server_type,
                        'server_ip': server_ip,
                        'query': current_domain,
                        'rtt': step_time,
                        'response_type': None,
                        'referral': None
                    }
                    
                    self.logger.info(f"  Response received (RTT: {step_time:.4f}s)")
                    self.logger.info(f"  Flags: {dns.flags.to_text(response.flags)}")
                    self.logger.info(f"  Answer count: {len(response.answer)}")
                    self.logger.info(f"  Authority count: {len(response.authority)}")
                    self.logger.info(f"  Additional count: {len(response.additional)}")
                    
                    # Check if we have an answer
                    if response.answer:
                        self.logger.info(f" ANSWER FOUND!")
                        step_log['response_type'] = 'ANSWER'
                        
                        # Extract answers
                        answers = []
                        for rrset in response.answer:
                            for rdata in rrset:
                                answer_str = str(rdata)
                                answers.append(answer_str)
                                self.logger.info(f"    -> {rrset.name} {rrset.ttl} {dns.rdatatype.to_text(rrset.rdtype)} {rdata}")
                        
                        step_log['answers'] = answers
                        query_log['steps'].append(step_log)
                        
                        return {
                            'success': True,
                            'answers': answers,
                            'steps': step_number,
                            'total_time': sum(s['rtt'] for s in query_log['steps'])
                        }
                    
                    # Check for referrals in authority section
                    if response.authority:
                        # Check if authority section contains SOA (indicates NXDOMAIN or no records)
                        has_soa = False
                        has_ns = False
                        for rrset in response.authority:
                            if rrset.rdtype == dns.rdatatype.SOA:
                                has_soa = True
                                self.logger.info(f"  SOA record received - domain exists but no {qtype} records found")
                                step_log['response_type'] = 'SOA'
                                query_log['steps'].append(step_log)
                            elif rrset.rdtype == dns.rdatatype.NS:
                                has_ns = True
                        
                        # If only SOA record (no NS records), this is the final answer (NXDOMAIN or no records)
                        if has_soa and not has_ns:
                            self.logger.info(f"  No {qtype} records exist for {domain}")
                            return {
                                'success': False,
                                'answers': [],
                                'steps': step_number,
                                'total_time': sum(s['rtt'] for s in query_log['steps']),
                                'error': f'No {qtype} records found'
                            }
                        
                        # Extract nameserver names from authority section
                        self.logger.info(f"  REFERRAL received")
                        step_log['response_type'] = 'REFERRAL'
                        
                        ns_names = []
                        for rrset in response.authority:
                            if rrset.rdtype == dns.rdatatype.NS:
                                for rdata in rrset:
                                    ns_name = str(rdata).rstrip('.')
                                    ns_names.append(ns_name)
                                    self.logger.info(f"    Nameserver: {ns_name}")
                        
                        # Extract nameserver IPs from additional section
                        ns_ips = []
                        for rrset in response.additional:
                            if rrset.rdtype == dns.rdatatype.A:
                                for rdata in rrset:
                                    ns_ip = str(rdata)
                                    ns_ips.append(ns_ip)
                                    self.logger.info(f"    NS IP: {ns_ip}")
                        
                        step_log['referral'] = {
                            'ns_names': ns_names,
                            'ns_ips': ns_ips
                        }
                        query_log['steps'].append(step_log)
                        
                        # If we have IPs, use them for next iteration
                        if ns_ips:
                            current_servers = ns_ips
                            break  # Move to next step with new servers
                        elif ns_names:
                            # Need to resolve nameserver names
                            resolved_ns_ips = []
                            for ns_name in ns_names[:3]:  # Limit to first 3
                                try:
                                    self.logger.info(f"  Resolving nameserver: {ns_name}")
                                    ns_resolver = dns.resolver.Resolver()
                                    ns_resolver.timeout = timeout
                                    ns_resolver.lifetime = timeout
                                    answers = ns_resolver.resolve(ns_name, 'A')
                                    for rdata in answers:
                                        resolved_ns_ips.append(str(rdata))
                                        self.logger.info(f"    Resolved to: {rdata}")
                                except Exception as e:
                                    self.logger.debug(f"  Failed to resolve NS {ns_name}: {e}")
                            
                            if resolved_ns_ips:
                                current_servers = resolved_ns_ips
                                break
                        
                        # If we couldn't get any IPs, this server failed
                        self.logger.warning(f"  No usable referrals from {server_ip}")
                        continue
                    
                    # No answer and no referral - check additional for hints
                    if response.additional:
                        self.logger.info(f"  Checking additional section for glue records")
                        ns_ips = []
                        for rrset in response.additional:
                            if rrset.rdtype == dns.rdatatype.A:
                                for rdata in rrset:
                                    ns_ip = str(rdata)
                                    ns_ips.append(ns_ip)
                                    self.logger.info(f"    Found glue: {ns_ip}")
                        
                        if ns_ips:
                            step_log['response_type'] = 'GLUE'
                            step_log['referral'] = {'ns_ips': ns_ips}
                            query_log['steps'].append(step_log)
                            current_servers = ns_ips
                            break
                    
                    # No useful information from this server
                    self.logger.warning(f"  No answer or referral from {server_ip}")
                    query_log['steps'].append(step_log)
                    
                except dns.exception.Timeout:
                    self.logger.warning(f"  Timeout querying {server_ip}")
                    continue
                except Exception as e:
                    self.logger.error(f"  Error querying {server_ip}: {str(e)}")
                    continue
            
            # If we've tried all servers and got nothing useful, fail
            if step_number > 1 and current_servers == self.ROOT_SERVERS:
                self.logger.error(f"Resolution failed: back to root servers without progress")
                return None
            
            # Safety check
            if not current_servers:
                self.logger.error(f"Resolution failed: no more servers to query")
                return None
    
    def get_statistics(self):
        """Get resolver statistics"""
        avg_latency = (self.statistics['total_latency'] / self.statistics['total_queries'] 
                      if self.statistics['total_queries'] > 0 else 0)
        
        return {
            'total_queries': self.statistics['total_queries'],
            'successful': self.statistics['successful'],
            'failed': self.statistics['failed'],
            'success_rate': (self.statistics['successful'] / self.statistics['total_queries'] * 100
                           if self.statistics['total_queries'] > 0 else 0),
            'cache_hits': self.statistics['cache_hits'],
            'cache_misses': self.statistics['cache_misses'],
            'average_latency': avg_latency,
            'queries_by_type': dict(self.statistics['queries_by_type'])
        }
    
    def print_statistics(self):
        """Print resolver statistics"""
        stats = self.get_statistics()
        
        print("\n" + "="*80)
        print("DNS RESOLVER STATISTICS")
        print("="*80)
        print(f"Total queries: {stats['total_queries']}")
        print(f"Successful: {stats['successful']}")
        print(f"Failed: {stats['failed']}")
        print(f"Success rate: {stats['success_rate']:.2f}%")
        print(f"Cache hits: {stats['cache_hits']}")
        print(f"Cache misses: {stats['cache_misses']}")
        print(f"Average latency: {stats['average_latency']:.4f} seconds")
        print(f"\nQueries by type:")
        for qtype, count in stats['queries_by_type'].items():
            print(f"  {qtype}: {count}")
        print("="*80 + "\n")
    
    def export_logs_to_json(self, output_file='logs/query_logs.json'):
        """Export detailed query logs to JSON"""
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else 'logs', exist_ok=True)
        
        data = {
            'statistics': self.get_statistics(),
            'queries': self.query_logs
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"Query logs exported to {output_file}")
    
    def export_logs_to_csv(self, output_file='logs/custom_dns.csv'):
        """Export query logs to CSV format"""
        import csv
        
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else 'logs', exist_ok=True)
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Timestamp', 'Domain', 'Query Type', 'Mode', 'Success', 
                'Total Time (s)', 'Steps', 'Cache Status', 'Answers', 'Error'
            ])
            
            for log in self.query_logs:
                writer.writerow([
                    log['timestamp'],
                    log['domain'],
                    log['qtype'],
                    log['mode'],
                    log['success'],
                    f"{log['total_time']:.4f}",
                    len(log['steps']),
                    log['cache_status'],
                    '; '.join(log['answers']) if log['answers'] else '',
                    log['error'] if log['error'] else ''
                ])
        
        print(f"Query logs exported to {output_file}")
