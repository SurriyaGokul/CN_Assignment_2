#!/usr/bin/env python3
"""
Custom DNS Resolver Server for Mininet
Runs on 10.0.0.5:53 and performs iterative DNS resolution

This server:
1. Listens on UDP port 53 for DNS queries from Mininet hosts
2. Performs iterative resolution (Root -> TLD -> Authoritative)
3. Logs all steps: timestamp, domain, server contacted, RTT, etc.
4. Supports both UDP and TCP for truncated responses
5. Returns answers to requesting host

Usage:
    On DNS host (10.0.0.5) in Mininet:
    sudo python3 custom_dns_server.py
"""

import socket
import socketserver
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
import dns.rdatatype
import dns.flags
import dns.resolver


class DNSResolverServer:
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
    
    def __init__(self, log_file='/tmp/dns_resolver.log', json_log='/tmp/dns_queries.json'):
        """Initialize the DNS resolver server"""
        self.log_file = log_file
        self.json_log = json_log
        self.cache = {}  # Simple cache: domain -> (answers, expiry_time)
        self.statistics = {
            'total_queries': 0,
            'successful': 0,
            'failed': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }
        self.query_logs = []
        self.lock = threading.Lock()
        
        # Setup logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Setup logging configuration"""
        self.logger = logging.getLogger('CustomDNSServer')
        self.logger.setLevel(logging.DEBUG)
        
        # File handler
        fh = logging.FileHandler(self.log_file, mode='a')
        fh.setLevel(logging.DEBUG)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)
        
        self.logger.info("="*80)
        self.logger.info("Custom DNS Resolver Server Starting on 0.0.0.0:53")
        self.logger.info("Mode: Iterative Resolution")
        self.logger.info("="*80)
    
    def resolve_iterative(self, domain, qtype='A', timeout=5):
        """
        Perform iterative DNS resolution
        
        Args:
            domain (str): Domain name to resolve
            qtype (str): Query type (A, AAAA, MX, etc.)
            timeout (int): Timeout in seconds
            
        Returns:
            dict: Resolution result with answers and steps
        """
        start_time = time.time()
        
        # Normalize domain
        if not domain.endswith('.'):
            domain = domain + '.'
        
        self.logger.info(f"\n{'='*80}")
        self.logger.info(f"NEW QUERY: {domain} (Type: {qtype})")
        self.logger.info(f"Resolution Mode: Iterative")
        
        # Create query log entry
        query_log = {
            'timestamp': datetime.now().isoformat(),
            'domain': domain,
            'qtype': qtype,
            'resolution_mode': 'iterative',
            'steps': [],
            'total_time': 0,
            'cache_status': 'MISS',
            'success': False,
            'answers': [],
            'error': None
        }
        
        try:
            # Check cache
            cache_key = f"{domain}:{qtype}"
            if cache_key in self.cache:
                cached_data, expiry = self.cache[cache_key]
                if time.time() < expiry:
                    self.logger.info(f"CACHE HIT for {domain}")
                    query_log['cache_status'] = 'HIT'
                    with self.lock:
                        self.statistics['cache_hits'] += 1
                    query_log['answers'] = cached_data
                    query_log['success'] = True
                    query_log['total_time'] = time.time() - start_time
                    return query_log
            
            with self.lock:
                self.statistics['cache_misses'] += 1
            
            # Perform iterative resolution
            current_servers = self.ROOT_SERVERS.copy()
            step_number = 0
            max_steps = 20
            
            while step_number < max_steps:
                step_number += 1
                
                # Try each server in the current list
                for server_ip in current_servers:
                    try:
                        step_start = time.time()
                        
                        # Determine server type
                        if step_number == 1 or server_ip in self.ROOT_SERVERS:
                            server_type = "ROOT"
                        elif step_number == 2:
                            server_type = "TLD"
                        else:
                            server_type = "AUTHORITATIVE"
                        
                        self.logger.info(f"\nStep {step_number}: Querying {server_type} server {server_ip}")
                        
                        # Create DNS query
                        query_msg = dns.message.make_query(domain, qtype)
                        query_msg.flags &= ~dns.flags.RD  # Disable recursion desired
                        
                        # Send query
                        try:
                            response = dns.query.udp(query_msg, server_ip, timeout=timeout)
                        except:
                            # Try TCP if UDP fails
                            response = dns.query.tcp(query_msg, server_ip, timeout=timeout)
                        
                        rtt = time.time() - step_start
                        
                        # Log step
                        step_log = {
                            'step': step_number,
                            'server_type': server_type,
                            'server_ip': server_ip,
                            'query': domain,
                            'rtt': rtt,
                            'response_type': None,
                            'referral': None,
                            'answers': []
                        }
                        
                        self.logger.info(f"  Response received in {rtt*1000:.2f}ms")
                        
                        # Check for answers
                        if response.answer:
                            answers = []
                            for rrset in response.answer:
                                for rdata in rrset:
                                    answer_str = str(rdata)
                                    answers.append(answer_str)
                                    self.logger.info(f"  Answer: {answer_str}")
                            
                            step_log['response_type'] = 'ANSWER'
                            step_log['answers'] = answers
                            query_log['steps'].append(step_log)
                            query_log['answers'] = answers
                            query_log['success'] = True
                            
                            # Cache the result (TTL = 300 seconds for simplicity)
                            self.cache[cache_key] = (answers, time.time() + 300)
                            
                            with self.lock:
                                self.statistics['successful'] += 1
                            
                            query_log['total_time'] = time.time() - start_time
                            self.logger.info(f"RESOLUTION SUCCESSFUL in {query_log['total_time']:.4f}s")
                            return query_log
                        
                        # Check for referrals (authority section)
                        elif response.authority:
                            ns_names = []
                            ns_ips = []
                            
                            # Extract nameserver names
                            for rrset in response.authority:
                                if rrset.rdtype == dns.rdatatype.NS:
                                    for rdata in rrset:
                                        ns_name = str(rdata.target)
                                        ns_names.append(ns_name)
                                        self.logger.info(f"  Referral to NS: {ns_name}")
                            
                            # Extract nameserver IPs from additional section
                            if response.additional:
                                for rrset in response.additional:
                                    if rrset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
                                        for rdata in rrset:
                                            ip = str(rdata)
                                            ns_ips.append(ip)
                                            self.logger.info(f"  NS IP: {ip}")
                            
                            # If no IPs in additional section, resolve NS names
                            if not ns_ips and ns_names:
                                self.logger.info("  Resolving NS names to IPs...")
                                for ns_name in ns_names[:3]:  # Limit to 3
                                    try:
                                        ns_query = dns.message.make_query(ns_name, 'A')
                                        ns_response = dns.query.udp(ns_query, server_ip, timeout=2)
                                        for ans in ns_response.answer:
                                            for rdata in ans:
                                                ns_ips.append(str(rdata))
                                    except:
                                        pass
                            
                            step_log['response_type'] = 'REFERRAL'
                            step_log['referral'] = {
                                'ns_names': ns_names,
                                'ns_ips': ns_ips
                            }
                            query_log['steps'].append(step_log)
                            
                            if ns_ips:
                                current_servers = ns_ips
                                break  # Move to next step with new servers
                            elif ns_names:
                                # Try to resolve using system resolver as fallback
                                resolved_ips = []
                                for ns_name in ns_names[:2]:
                                    try:
                                        import socket
                                        ip = socket.gethostbyname(ns_name.rstrip('.'))
                                        resolved_ips.append(ip)
                                    except:
                                        pass
                                if resolved_ips:
                                    current_servers = resolved_ips
                                    break
                        
                        else:
                            # No answer or referral
                            step_log['response_type'] = 'EMPTY'
                            query_log['steps'].append(step_log)
                            
                    except Exception as e:
                        self.logger.warning(f"  Error querying {server_ip}: {str(e)}")
                        continue
                
                # If we've tried all servers without success, break
                if step_number > 1 and not any(step['response_type'] == 'REFERRAL' for step in query_log['steps'][-len(current_servers):]):
                    break
            
            # Resolution failed
            if not query_log['success']:
                query_log['error'] = 'No answer found after iterative resolution'
                with self.lock:
                    self.statistics['failed'] += 1
                self.logger.warning(f"RESOLUTION FAILED for {domain}")
            
            query_log['total_time'] = time.time() - start_time
            return query_log
            
        except Exception as e:
            self.logger.error(f"ERROR resolving {domain}: {str(e)}")
            query_log['error'] = str(e)
            query_log['total_time'] = time.time() - start_time
            with self.lock:
                self.statistics['failed'] += 1
            return query_log
    
    def save_query_log(self, query_log):
        """Save query log to JSON file"""
        with self.lock:
            self.query_logs.append(query_log)
            self.statistics['total_queries'] += 1
            
            # Periodically save to file
            if len(self.query_logs) % 10 == 0:
                self._write_logs_to_file()
    
    def _write_logs_to_file(self):
        """Write accumulated logs to JSON file"""
        try:
            data = {
                'statistics': self.statistics.copy(),
                'queries': self.query_logs.copy()
            }
            with open(self.json_log, 'w') as f:
                json.dump(data, f, indent=2)
            self.logger.info(f"Saved {len(self.query_logs)} query logs to {self.json_log}")
        except Exception as e:
            self.logger.error(f"Error writing logs: {e}")
    
    def shutdown(self):
        """Shutdown server and save logs"""
        self.logger.info("Shutting down DNS server...")
        self._write_logs_to_file()
        self.logger.info("All logs saved")


class DNSUDPHandler(socketserver.BaseRequestHandler):
    """Handle UDP DNS requests"""
    
    def handle(self):
        data = self.request[0]
        sock = self.request[1]
        client_addr = self.client_address
        
        try:
            # Parse DNS request
            request = dns.message.from_wire(data)
            
            # Get query details
            if request.question:
                qname = str(request.question[0].name)
                qtype = dns.rdatatype.to_text(request.question[0].rdtype)
                
                self.server.resolver.logger.info(f"Received query from {client_addr[0]}: {qname} ({qtype})")
                
                # Resolve the query
                result = self.server.resolver.resolve_iterative(qname, qtype)
                self.server.resolver.save_query_log(result)
                
                # Build response
                response = dns.message.make_response(request)
                response.flags |= dns.flags.AA  # Authoritative answer
                
                if result['success'] and result['answers']:
                    # Add answers to response
                    for answer_str in result['answers']:
                        try:
                            # Create answer RR
                            if qtype == 'A':
                                import dns.rrset
                                import dns.rdataclass
                                rrset = dns.rrset.RRset(request.question[0].name, dns.rdataclass.IN, dns.rdatatype.A)
                                rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, answer_str)
                                rrset.add(rdata, ttl=300)
                                response.answer.append(rrset)
                        except:
                            pass
                
                # Send response
                sock.sendto(response.to_wire(), client_addr)
                
        except Exception as e:
            self.server.resolver.logger.error(f"Error handling request: {e}")


class CustomDNSServer(socketserver.ThreadingUDPServer):
    """Threaded UDP DNS Server"""
    
    def __init__(self, server_address, handler_class):
        self.resolver = DNSResolverServer()
        socketserver.ThreadingUDPServer.__init__(self, server_address, handler_class)
        self.allow_reuse_address = True


def main():
    """Main function to start DNS server"""
    HOST = '0.0.0.0'  # Listen on all interfaces
    PORT = 53
    
    print("="*80)
    print("Custom DNS Resolver Server for Mininet")
    print("="*80)
    print(f"Starting server on {HOST}:{PORT}")
    print("Press Ctrl+C to stop")
    print("="*80)
    
    server = CustomDNSServer((HOST, PORT), DNSUDPHandler)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\nShutting down server...")
        server.resolver.shutdown()
        server.shutdown()
        print("Server stopped")


if __name__ == '__main__':
    main()
