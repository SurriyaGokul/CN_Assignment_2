#!/usr/bin/env python3
"""
Custom DNS Resolver Server for Mininet with Comprehensive Logging
Runs on 10.0.0.5:53 and performs iterative DNS resolution
Logs ALL required fields: timestamp, domain, mode, servers, steps, RTT, total time, cache status
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
    """Custom DNS Resolver with Iterative Resolution and Comprehensive Logging"""
    
    ROOT_SERVERS = [
        '198.41.0.4',      # a.root-servers.net
        '199.9.14.201',    # b.root-servers.net
        '192.33.4.12',     # c.root-servers.net
        '199.7.91.13',     # d.root-servers.net
        '192.203.230.10',  # e.root-servers.net
    ]
    
    def __init__(self, log_file='/tmp/dns_resolver.log', json_log='/tmp/dns_queries.json'):
        """Initialize the DNS resolver server"""
        self.log_file = log_file
        self.json_log = json_log
        self.cache = {}
        self.statistics = {
            'total_queries': 0,
            'successful': 0,
            'failed': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }
        self.query_logs = []
        self.lock = threading.Lock()
        
        self._setup_logging()
        
    def _setup_logging(self):
        """Setup logging configuration"""
        self.logger = logging.getLogger('CustomDNSServer')
        self.logger.setLevel(logging.DEBUG)
        
        # File handler
        fh = logging.FileHandler(self.log_file, mode='w')
        fh.setLevel(logging.DEBUG)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Formatter with all required fields
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
        self.logger.info("Comprehensive Logging: ENABLED")
        self.logger.info("="*80)
    
    def resolve_iterative(self, domain, qtype='A', timeout=5):
        """
        Perform iterative DNS resolution with COMPREHENSIVE logging
        Logs: timestamp, domain, mode, servers, steps, RTT, total time, cache status
        """
        start_time = time.time()
        
        # Normalize domain
        if not domain.endswith('.'):
            domain = domain + '.'
        
        self.logger.info(f"\n{'='*80}")
        self.logger.info(f"NEW QUERY: {domain} (Type: {qtype})")
        self.logger.info(f"Timestamp: {datetime.now().isoformat()}")
        self.logger.info(f"Resolution Mode: Iterative")
        
        # Create comprehensive query log entry with ALL required fields
        query_log = {
            # a. Timestamp
            'timestamp': datetime.now().isoformat(),
            
            # b. Domain name queried
            'domain': domain,
            
            # c. Resolution mode
            'resolution_mode': 'iterative',
            
            'qtype': qtype,
            
            # d, e, f, g - Will be populated in resolution_path
            'resolution_path': [],  # Each step contains: server IP, step type, response/referral, RTT
            
            # h. Total time to resolution
            'resolution_time_ms': 0,
            
            # i. Cache status (HIT / MISS)
            'cache_status': 'MISS',
            
            'success': False,
            'final_answer': None,
            'answers': [],
            'answer_rrsets': [],
            'error': None
        }
        
        try:
            # Check cache (i. Cache status)
            cache_key = f"{domain}:{qtype}"
            if cache_key in self.cache:
                cached_data, cached_rrsets, expiry = self.cache[cache_key]
                if time.time() < expiry:
                    self.logger.info(f"CACHE STATUS: HIT for {domain}")
                    query_log['cache_status'] = 'HIT'
                    with self.lock:
                        self.statistics['cache_hits'] += 1
                    query_log['answers'] = cached_data
                    query_log['final_answer'] = cached_data[0] if cached_data else None
                    query_log['answer_rrsets'] = cached_rrsets
                    query_log['success'] = True
                    query_log['resolution_time_ms'] = round((time.time() - start_time) * 1000, 2)
                    
                    self.logger.info(f"RESOLVED from cache in {query_log['resolution_time_ms']:.2f}ms")
                    return query_log
            
            # Cache miss
            self.logger.info(f"CACHE STATUS: MISS for {domain}")
            query_log['cache_status'] = 'MISS'
            
            with self.lock:
                self.statistics['cache_misses'] += 1
            
            # Perform iterative resolution
            current_servers = self.ROOT_SERVERS.copy()
            step_number = 0
            max_steps = 15
            
            while step_number < max_steps:
                step_number += 1
                
                # Try each server in the current list
                for server_ip in current_servers:
                    try:
                        step_start = time.time()
                        
                        # e. Determine step of resolution (Root / TLD / Authoritative)
                        if step_number == 1 or server_ip in self.ROOT_SERVERS:
                            server_type = "ROOT"
                        elif step_number == 2:
                            server_type = "TLD"
                        else:
                            server_type = "AUTHORITATIVE"
                        
                        # d. DNS server IP contacted
                        self.logger.info(f"\nStep {step_number}: Querying {server_type} server")
                        self.logger.info(f"   DNS Server IP: {server_ip}")
                        
                        # Create DNS query
                        query_msg = dns.message.make_query(domain, qtype)
                        query_msg.flags &= ~dns.flags.RD  # Disable recursion desired
                        
                        # Send query and measure RTT
                        try:
                            response = dns.query.udp(query_msg, server_ip, timeout=timeout)
                        except:
                            try:
                                response = dns.query.tcp(query_msg, server_ip, timeout=timeout)
                            except:
                                continue
                        
                        # g. Round-trip time to that server
                        rtt_ms = round((time.time() - step_start) * 1000, 2)
                        
                        # Create step log with ALL required fields
                        step_log = {
                            'step': step_number,
                            'server': server_ip,           # d. DNS server IP contacted
                            'server_type': server_type,    # e. Step of resolution
                            'query': domain,
                            'rtt_ms': rtt_ms,              # g. Round-trip time
                            'response_type': None,         # f. Response or referral received
                            'referral': None,
                            'answers': []
                        }
                        
                        self.logger.info(f"   RTT: {rtt_ms:.2f}ms")
                        
                        # Check for answers
                        if response.answer:
                            answers = []
                            answer_rrsets = []
                            
                            for rrset in response.answer:
                                answer_rrsets.append(rrset)
                                for rdata in rrset:
                                    answer_str = str(rdata)
                                    answers.append(answer_str)
                                    self.logger.info(f"   Answer: {answer_str}")
                            
                            # f. Response received
                            step_log['response_type'] = 'ANSWER'
                            step_log['answers'] = answers
                            query_log['resolution_path'].append(step_log)
                            query_log['answers'] = answers
                            query_log['final_answer'] = answers[0] if answers else None
                            query_log['answer_rrsets'] = answer_rrsets
                            query_log['success'] = True
                            
                            # Cache the result (TTL = 300 seconds)
                            self.cache[cache_key] = (answers, answer_rrsets, time.time() + 300)
                            
                            with self.lock:
                                self.statistics['successful'] += 1
                            
                            # h. Total time to resolution
                            query_log['resolution_time_ms'] = round((time.time() - start_time) * 1000, 2)
                            
                            self.logger.info(f"\nRESOLUTION SUCCESSFUL")
                            self.logger.info(f"   Total Time: {query_log['resolution_time_ms']:.2f}ms")
                            self.logger.info(f"   Total Servers Contacted: {len(query_log['resolution_path'])}")
                            self.logger.info(f"   Final Answer: {query_log['final_answer']}")
                            
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
                                        self.logger.info(f"   Referral to NS: {ns_name}")
                            
                            # Extract nameserver IPs from additional section
                            if response.additional:
                                for rrset in response.additional:
                                    if rrset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
                                        for rdata in rrset:
                                            ip = str(rdata)
                                            ns_ips.append(ip)
                                            self.logger.info(f"   NS IP: {ip}")
                            
                            # If no IPs in additional section, resolve NS names
                            if not ns_ips and ns_names:
                                self.logger.info("   Resolving NS names to IPs...")
                                for ns_name in ns_names[:2]:
                                    try:
                                        ns_query = dns.message.make_query(ns_name, 'A')
                                        ns_response = dns.query.udp(ns_query, self.ROOT_SERVERS[0], timeout=3)
                                        if ns_response.answer:
                                            for ans in ns_response.answer:
                                                for rdata in ans:
                                                    if ans.rdtype == dns.rdatatype.A:
                                                        ns_ips.append(str(rdata))
                                                        self.logger.info(f"      {ns_name} -> {str(rdata)}")
                                    except:
                                        pass
                            
                            # f. Referral received
                            step_log['response_type'] = 'REFERRAL'
                            step_log['referral'] = {
                                'ns_names': ns_names,
                                'ns_ips': ns_ips
                            }
                            query_log['resolution_path'].append(step_log)
                            
                            if ns_ips:
                                current_servers = ns_ips
                                break
                        
                        else:
                            step_log['response_type'] = 'EMPTY'
                            query_log['resolution_path'].append(step_log)
                            self.logger.warning(f"   Empty response")
                            
                    except Exception as e:
                        self.logger.warning(f"   Error querying {server_ip}: {str(e)}")
                        continue
                
                # Check if we got a referral in this iteration
                if not query_log['resolution_path'] or query_log['resolution_path'][-1]['response_type'] != 'REFERRAL':
                    break
            
            # Resolution failed
            if not query_log['success']:
                query_log['error'] = 'No answer found after iterative resolution'
                with self.lock:
                    self.statistics['failed'] += 1
                self.logger.warning(f"\nRESOLUTION FAILED for {domain}")
            
            # h. Total time to resolution
            query_log['resolution_time_ms'] = round((time.time() - start_time) * 1000, 2)
            
            return query_log
            
        except Exception as e:
            self.logger.error(f"\nERROR resolving {domain}: {str(e)}")
            query_log['error'] = str(e)
            query_log['resolution_time_ms'] = round((time.time() - start_time) * 1000, 2)
            with self.lock:
                self.statistics['failed'] += 1
            return query_log
    
    def save_query_log(self, query_log):
        """Save query log to JSON file with all required fields"""
        log_copy = query_log.copy()
        log_copy.pop('answer_rrsets', None)  # Remove unpicklable objects
        
        with self.lock:
            self.query_logs.append(log_copy)
            self.statistics['total_queries'] += 1
            
            # Write to file every 5 queries
            if len(self.query_logs) % 5 == 0:
                self._write_logs_to_file()
    
    def _write_logs_to_file(self):
        """Write accumulated logs to JSON file"""
        try:
            data = {
                'metadata': {
                    'server_start': datetime.now().isoformat(),
                    'mode': 'iterative',
                    'caching_enabled': True
                },
                'statistics': self.statistics.copy(),
                'queries': self.query_logs.copy()
            }
            with open(self.json_log, 'w') as f:
                json.dump(data, f, indent=2)
            
            self.logger.debug(f"Logs written to {self.json_log}")
        except Exception as e:
            self.logger.error(f"Error writing logs: {e}")
    
    def shutdown(self):
        """Shutdown server and save logs"""
        self.logger.info("\n" + "="*80)
        self.logger.info("Shutting down DNS server...")
        self.logger.info(f"Final Statistics:")
        self.logger.info(f"   Total Queries: {self.statistics['total_queries']}")
        self.logger.info(f"   Successful: {self.statistics['successful']}")
        self.logger.info(f"   Failed: {self.statistics['failed']}")
        self.logger.info(f"   Cache Hits: {self.statistics['cache_hits']}")
        self.logger.info(f"   Cache Misses: {self.statistics['cache_misses']}")
        
        self._write_logs_to_file()
        self.logger.info(f"All logs saved to {self.json_log}")
        self.logger.info("="*80)


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
                
                self.server.resolver.logger.info(f"\nQuery from {client_addr[0]}: {qname} ({qtype})")
                
                # Resolve the query with comprehensive logging
                result = self.server.resolver.resolve_iterative(qname, qtype)
                self.server.resolver.save_query_log(result)
                
                # Build response
                response = dns.message.make_response(request)
                response.flags |= dns.flags.AA  # Authoritative answer
                response.flags |= dns.flags.RA  # Recursion available
                
                if result['success'] and result.get('answer_rrsets'):
                    for rrset in result['answer_rrsets']:
                        response.answer.append(rrset)
                    
                    self.server.resolver.logger.info(f"Sending response to {client_addr[0]}")
                else:
                    response.set_rcode(dns.rcode.NXDOMAIN)
                    self.server.resolver.logger.info(f"Sending NXDOMAIN to {client_addr[0]}")
                
                # Send response
                sock.sendto(response.to_wire(), client_addr)
                
        except Exception as e:
            self.server.resolver.logger.error(f"Error handling request from {client_addr[0]}: {e}")
            import traceback
            self.server.resolver.logger.error(traceback.format_exc())


class CustomDNSServer(socketserver.ThreadingUDPServer):
    """Threaded UDP DNS Server"""
    
    def __init__(self, server_address, handler_class):
        self.resolver = DNSResolverServer()
        socketserver.ThreadingUDPServer.__init__(self, server_address, handler_class)
        self.allow_reuse_address = True


def main():
    """Main function to start DNS server"""
    HOST = '0.0.0.0'
    PORT = 53
    
    print("="*80)
    print("Custom DNS Resolver Server for Mininet")
    print("Comprehensive Logging: ALL Required Fields")
    print("="*80)
    print(f"Starting server on {HOST}:{PORT}")
    print(f"Logs: /tmp/dns_resolver.log")
    print(f"JSON: /tmp/dns_queries.json")
    print("Press Ctrl+C to stop")
    print("="*80)
    
    server = CustomDNSServer((HOST, PORT), DNSUDPHandler)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n" + "="*80)
        print("Received shutdown signal")
        server.resolver.shutdown()
        server.shutdown()
        print("Server stopped cleanly")
        print("="*80)


if __name__ == '__main__':
    main()