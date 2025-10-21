try:
    from scapy.all import rdpcap, DNS, DNSQR, DNSRR, IP, UDP, TCP
    from scapy.layers.dns import DNSQR, DNSRR
except ImportError:
    print("Error: scapy is required. Install it with: pip install scapy")
    exit(1)

import os
import json
from collections import defaultdict
from datetime import datetime


class DNSPacketParser:
    """Parser for DNS packets in PCAP files"""
    
    def __init__(self, pcap_file):
        """
        Initialize the parser with a PCAP file
        
        Args:
            pcap_file (str): Path to the PCAP file
        """
        self.pcap_file = pcap_file
        self.packets = []
        self.dns_queries = []
        self.dns_responses = []
        self.statistics = defaultdict(int)
        
    def load_pcap(self):
        """Load PCAP file using scapy"""
        if not os.path.exists(self.pcap_file):
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")
        
        print(f"Loading PCAP file: {self.pcap_file}")
        self.packets = rdpcap(self.pcap_file)
        print(f"Loaded {len(self.packets)} packets")
        return len(self.packets)
    
    def parse_dns_packet(self, packet):
        """
        Parse a single DNS packet and extract relevant information
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict: Parsed DNS packet information
        """
        dns_info = {
            'timestamp': float(packet.time),
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'transaction_id': None,
            'is_query': False,
            'is_response': False,
            'queries': [],
            'answers': [],
            'authorities': [],
            'additional': [],
            'query_type': None,
            'response_code': None,
            'flags': {}
        }
        
        # Extract IP information
        if IP in packet:
            dns_info['src_ip'] = packet[IP].src
            dns_info['dst_ip'] = packet[IP].dst
        
        # Extract UDP/TCP port information
        if UDP in packet:
            dns_info['src_port'] = packet[UDP].sport
            dns_info['dst_port'] = packet[UDP].dport
        elif TCP in packet:
            dns_info['src_port'] = packet[TCP].sport
            dns_info['dst_port'] = packet[TCP].dport
        
        # Extract DNS information
        if DNS in packet:
            dns_layer = packet[DNS]
            dns_info['transaction_id'] = dns_layer.id
            
            # Determine if query or response
            dns_info['is_query'] = dns_layer.qr == 0
            dns_info['is_response'] = dns_layer.qr == 1
            
            # Extract flags
            dns_info['flags'] = {
                'qr': dns_layer.qr,  # 0=query, 1=response
                'opcode': dns_layer.opcode,
                'aa': dns_layer.aa,  # Authoritative answer
                'tc': dns_layer.tc,  # Truncated
                'rd': dns_layer.rd,  # Recursion desired
                'ra': dns_layer.ra,  # Recursion available
                'z': dns_layer.z,    # Reserved
                'rcode': dns_layer.rcode  # Response code
            }
            
            dns_info['response_code'] = dns_layer.rcode
            
            # Parse queries
            if dns_layer.qd:
                for i in range(dns_layer.qdcount):
                    try:
                        query = dns_layer.qd[i] if dns_layer.qdcount > 1 else dns_layer.qd
                        query_info = {
                            'name': query.qname.decode() if isinstance(query.qname, bytes) else str(query.qname),
                            'type': query.qtype,
                            'type_name': self._get_query_type_name(query.qtype),
                            'class': query.qclass
                        }
                        dns_info['queries'].append(query_info)
                        if not dns_info['query_type']:
                            dns_info['query_type'] = query_info['type_name']
                    except Exception as e:
                        print(f"Error parsing query: {e}")
            
            # Parse answers
            if dns_layer.an:
                for i in range(dns_layer.ancount):
                    try:
                        if dns_layer.ancount > 1:
                            answer = dns_layer.an[i]
                        else:
                            answer = dns_layer.an
                        answer_info = self._parse_resource_record(answer)
                        dns_info['answers'].append(answer_info)
                    except Exception as e:
                        print(f"Error parsing answer: {e}")
            
            # Parse authority records
            if dns_layer.ns:
                for i in range(dns_layer.nscount):
                    try:
                        if dns_layer.nscount > 1:
                            auth = dns_layer.ns[i]
                        else:
                            auth = dns_layer.ns
                        auth_info = self._parse_resource_record(auth)
                        dns_info['authorities'].append(auth_info)
                    except Exception as e:
                        print(f"Error parsing authority: {e}")
            
            # Parse additional records
            if dns_layer.ar:
                for i in range(dns_layer.arcount):
                    try:
                        if dns_layer.arcount > 1:
                            add = dns_layer.ar[i]
                        else:
                            add = dns_layer.ar
                        add_info = self._parse_resource_record(add)
                        dns_info['additional'].append(add_info)
                    except Exception as e:
                        print(f"Error parsing additional: {e}")
        
        return dns_info
    
    def _parse_resource_record(self, rr):
        """Parse a DNS resource record"""
        rr_info = {
            'name': rr.rrname.decode() if isinstance(rr.rrname, bytes) else str(rr.rrname),
            'type': rr.type,
            'type_name': self._get_query_type_name(rr.type),
            'class': rr.rclass,
            'ttl': rr.ttl,
            'rdata': None
        }
        
        # Extract rdata based on type
        try:
            if rr.type == 1:  # A record
                rr_info['rdata'] = str(rr.rdata)
            elif rr.type == 28:  # AAAA record
                rr_info['rdata'] = str(rr.rdata)
            elif rr.type == 5:  # CNAME
                rr_info['rdata'] = rr.rdata.decode() if isinstance(rr.rdata, bytes) else str(rr.rdata)
            elif rr.type == 2:  # NS
                rr_info['rdata'] = rr.rdata.decode() if isinstance(rr.rdata, bytes) else str(rr.rdata)
            elif rr.type == 15:  # MX
                rr_info['rdata'] = str(rr.rdata)
            elif rr.type == 16:  # TXT
                rr_info['rdata'] = str(rr.rdata)
            else:
                rr_info['rdata'] = str(rr.rdata)
        except Exception as e:
            rr_info['rdata'] = f"<parse error: {e}>"
        
        return rr_info
    
    def _get_query_type_name(self, qtype):
        """Convert DNS query type number to name"""
        type_map = {
            1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
            15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY'
        }
        return type_map.get(qtype, f'TYPE{qtype}')
    
    def parse_all(self):
        """Parse all DNS packets in the PCAP file"""
        if not self.packets:
            self.load_pcap()
        
        dns_packet_count = 0
        for packet in self.packets:
            if DNS in packet:
                dns_packet_count += 1
                dns_info = self.parse_dns_packet(packet)
                
                # Categorize as query or response
                if dns_info['is_query']:
                    self.dns_queries.append(dns_info)
                    self.statistics['queries'] += 1
                elif dns_info['is_response']:
                    self.dns_responses.append(dns_info)
                    self.statistics['responses'] += 1
                
                # Update statistics
                if dns_info['query_type']:
                    self.statistics[f"type_{dns_info['query_type']}"] += 1
        
        self.statistics['total_packets'] = len(self.packets)
        self.statistics['dns_packets'] = dns_packet_count
        
        print(f"Parsed {dns_packet_count} DNS packets ({self.statistics['queries']} queries, {self.statistics['responses']} responses)")
        
        return self.dns_queries, self.dns_responses
    
    def get_statistics(self):
        """Get parsing statistics"""
        return dict(self.statistics)
    
    def print_summary(self):
        """Print a summary of parsed DNS traffic"""
        print("\n" + "="*60)
        print(f"DNS Traffic Summary for {os.path.basename(self.pcap_file)}")
        print("="*60)
        print(f"Total packets: {self.statistics['total_packets']}")
        print(f"DNS packets: {self.statistics['dns_packets']}")
        print(f"  - Queries: {self.statistics['queries']}")
        print(f"  - Responses: {self.statistics['responses']}")
        print("\nQuery Types:")
        for key, value in sorted(self.statistics.items()):
            if key.startswith('type_'):
                print(f"  - {key.replace('type_', '')}: {value}")
        print("="*60 + "\n")
    
    def export_to_json(self, output_file):
        """
        Export parsed DNS data to JSON file
        
        Args:
            output_file (str): Path to output JSON file
        """
        data = {
            'pcap_file': self.pcap_file,
            'statistics': self.get_statistics(),
            'queries': self.dns_queries,
            'responses': self.dns_responses
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"Exported to {output_file}")
    
    def export_to_csv(self, output_file):
        """
        Export parsed DNS data to CSV file
        
        Args:
            output_file (str): Path to output CSV file
        """
        import csv
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Source IP', 'Dest IP', 'Type', 'Transaction ID', 
                           'Query/Response', 'Query Name', 'Query Type', 'Response Code', 'Answer'])
            
            # Write queries
            for query in self.dns_queries:
                timestamp = datetime.fromtimestamp(query['timestamp']).strftime('%Y-%m-%d %H:%M:%S.%f')
                query_name = query['queries'][0]['name'] if query['queries'] else ''
                writer.writerow([
                    timestamp,
                    query['src_ip'],
                    query['dst_ip'],
                    'DNS',
                    query['transaction_id'],
                    'Query',
                    query_name,
                    query['query_type'],
                    '',
                    ''
                ])
            
            # Write responses
            for response in self.dns_responses:
                timestamp = datetime.fromtimestamp(response['timestamp']).strftime('%Y-%m-%d %H:%M:%S.%f')
                query_name = response['queries'][0]['name'] if response['queries'] else ''
                answer = response['answers'][0]['rdata'] if response['answers'] else ''
                writer.writerow([
                    timestamp,
                    response['src_ip'],
                    response['dst_ip'],
                    'DNS',
                    response['transaction_id'],
                    'Response',
                    query_name,
                    response['query_type'],
                    response['response_code'],
                    answer
                ])
        
        print(f"Exported to {output_file}")
