#!/usr/bin/env python3
"""
Generate Visualizations for PCAP_1_H1 DNS Analysis
Creates the required graphs as per Part D of the assignment:
1. Latency per query (first 10)
2. Number of DNS servers visited per query (first 10)

Usage:
    python3 generate_visualizations.py /tmp/dns_queries.json
"""

import json
import sys
import os

# Auto-install matplotlib if not present
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    import numpy as np
    import matplotlib
    matplotlib.use('Agg')
except ImportError:
    print("  📦 Installing matplotlib and seaborn...")
    import subprocess
    subprocess.run([sys.executable, '-m', 'pip', 'install', '-q', 'matplotlib', 'seaborn'], 
                   check=True)
    import matplotlib.pyplot as plt
    import seaborn as sns
    import numpy as np
    import matplotlib
    matplotlib.use('Agg')

from pathlib import Path

# Set style
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (14, 6)
plt.rcParams['font.size'] = 10


def load_query_logs(json_file):
    """Load query logs from JSON file"""
    print(f"Loading query logs from: {json_file}")
    
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    queries = data.get('queries', [])
    stats = data.get('statistics', {})
    
    print(f"Loaded {len(queries)} queries")
    print(f"Statistics: {stats}")
    
    return queries, stats


def plot_latency_first_10(queries, output_dir):
    """Plot latency for first 10 queries"""
    print("\nGenerating latency plot for first 10 queries...")
    
    first_10 = queries[:10]
    
    # Extract data - handle both 'total_time' and 'resolution_time_ms' fields
    domains = []
    latencies = []
    statuses = []
    
    for q in first_10:
        # Get domain name
        domain = q.get('domain', 'unknown')
        domain = domain.replace('.', '').replace('www', '')[:20]
        domains.append(domain)
        
        # Get latency (handle different field names)
        if 'resolution_time_ms' in q:
            latency = q['resolution_time_ms']
        elif 'total_time' in q:
            latency = q['total_time'] * 1000  # Convert to ms
        else:
            latency = 0
        latencies.append(latency)
        
        # Get success status
        statuses.append(q.get('success', False))
    
    # Create color map
    colors = ['#2ecc71' if s else '#e74c3c' for s in statuses]
    
    # Create figure
    fig, ax = plt.subplots(figsize=(14, 6))
    
    # Create bar plot
    bars = ax.bar(range(len(domains)), latencies, color=colors, alpha=0.8, 
                  edgecolor='black', linewidth=1.2)
    
    # Customize
    ax.set_xlabel('Domain Name', fontsize=12, fontweight='bold')
    ax.set_ylabel('Latency (milliseconds)', fontsize=12, fontweight='bold')
    ax.set_title('DNS Query Latency - First 10 Queries (PCAP_1_H1)\nCustom DNS Resolver (10.0.0.5) - Iterative Mode', 
                 fontsize=14, fontweight='bold', pad=20)
    
    # X-axis labels
    ax.set_xticks(range(len(domains)))
    ax.set_xticklabels(domains, rotation=45, ha='right')
    
    # Grid
    ax.yaxis.grid(True, linestyle='--', alpha=0.7)
    ax.set_axisbelow(True)
    
    # Value labels on bars
    for bar, lat, status in zip(bars, latencies, statuses):
        height = bar.get_height()
        label = f'{lat:.1f}ms'
        if not status:
            label += '\n(Failed)'
        ax.text(bar.get_x() + bar.get_width()/2., height,
               label, ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    # Legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='#2ecc71', edgecolor='black', label='Successful Resolution'),
        Patch(facecolor='#e74c3c', edgecolor='black', label='Failed Resolution')
    ]
    ax.legend(handles=legend_elements, loc='upper right', fontsize=10)
    
    plt.tight_layout()
    
    # Save
    output_path = os.path.join(output_dir, 'h1_latency_first_10_queries.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_path}")
    
    try:
        plt.savefig(output_path.replace('.png', '.pdf'), bbox_inches='tight')
        print(f"✓ Saved: {output_path.replace('.png', '.pdf')}")
    except:
        pass
    
    plt.close()


def plot_servers_visited_first_10(queries, output_dir):
    """Plot number of DNS servers visited for first 10 queries"""
    print("\nGenerating DNS servers visited plot for first 10 queries...")
    
    first_10 = queries[:10]
    
    # Extract data - handle different field names
    domains = []
    num_servers = []
    statuses = []
    
    for q in first_10:
        # Get domain name
        domain = q.get('domain', 'unknown')
        domain = domain.replace('.', '').replace('www', '')[:20]
        domains.append(domain)
        
        # Get number of servers (handle different field names)
        if 'resolution_path' in q:
            num = len(q['resolution_path'])
        elif 'steps' in q:
            num = len(q['steps'])
        else:
            num = 0
        num_servers.append(num)
        
        # Get success status
        statuses.append(q.get('success', False))
    
    # Create color map
    colors = []
    for steps, success in zip(num_servers, statuses):
        if not success or steps == 0:
            colors.append('#e74c3c')  # Red for failed
        elif steps <= 2:
            colors.append('#2ecc71')  # Green for quick
        elif steps == 3:
            colors.append('#f39c12')  # Orange for medium
        else:
            colors.append('#3498db')  # Blue for many
    
    # Create figure
    fig, ax = plt.subplots(figsize=(14, 6))
    
    # Create bar plot
    bars = ax.bar(range(len(domains)), num_servers, color=colors, alpha=0.8,
                  edgecolor='black', linewidth=1.2)
    
    # Customize
    ax.set_xlabel('Domain Name', fontsize=12, fontweight='bold')
    ax.set_ylabel('Number of DNS Servers Visited', fontsize=12, fontweight='bold')
    ax.set_title('DNS Servers Visited per Query - First 10 Queries (PCAP_1_H1)\nCustom DNS Resolver (10.0.0.5) - Iterative Resolution', 
                 fontsize=14, fontweight='bold', pad=20)
    
    # X-axis labels
    ax.set_xticks(range(len(domains)))
    ax.set_xticklabels(domains, rotation=45, ha='right')
    
    # Y-axis integers only
    ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))
    
    # Grid
    ax.yaxis.grid(True, linestyle='--', alpha=0.7)
    ax.set_axisbelow(True)
    
    # Value labels
    for bar, steps, status in zip(bars, num_servers, statuses):
        height = bar.get_height()
        if steps == 0:
            label = 'Failed\n(0 servers)'
        else:
            label = f'{steps}\nservers'
        ax.text(bar.get_x() + bar.get_width()/2., height,
               label, ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    # Legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='#2ecc71', edgecolor='black', label='Quick Resolution (≤2 servers)'),
        Patch(facecolor='#f39c12', edgecolor='black', label='Medium (3 servers)'),
        Patch(facecolor='#3498db', edgecolor='black', label='Many Steps (>3 servers)'),
        Patch(facecolor='#e74c3c', edgecolor='black', label='Failed Resolution')
    ]
    ax.legend(handles=legend_elements, loc='upper right', fontsize=10)
    
    plt.tight_layout()
    
    # Save
    output_path = os.path.join(output_dir, 'h1_servers_visited_first_10_queries.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_path}")
    
    try:
        plt.savefig(output_path.replace('.png', '.pdf'), bbox_inches='tight')
        print(f"✓ Saved: {output_path.replace('.png', '.pdf')}")
    except:
        pass
    
    plt.close()


def plot_resolution_steps_breakdown(queries, output_dir):
    """Plot breakdown of resolution steps"""
    print("\nGenerating resolution steps breakdown...")
    
    first_10 = queries[:10]
    
    domains = []
    root_counts = []
    tld_counts = []
    auth_counts = []
    
    for q in first_10:
        domain = q.get('domain', 'unknown')
        domain = domain.replace('.', '').replace('www', '')[:20]
        domains.append(domain)
        
        # Get resolution path (handle different field names)
        if 'resolution_path' in q:
            steps = q['resolution_path']
        elif 'steps' in q:
            steps = q['steps']
        else:
            steps = []
        
        # Count server types
        root = sum(1 for step in steps if step.get('server_type') == 'ROOT')
        tld = sum(1 for step in steps if step.get('server_type') == 'TLD')
        auth = sum(1 for step in steps if step.get('server_type') in ['AUTHORITATIVE', 'AUTH'])
        
        root_counts.append(root)
        tld_counts.append(tld)
        auth_counts.append(auth)
    
    # Create figure
    fig, ax = plt.subplots(figsize=(14, 6))
    
    # Stacked bar plot
    x = np.arange(len(domains))
    width = 0.6
    
    p1 = ax.bar(x, root_counts, width, label='Root Servers', 
                color='#e74c3c', alpha=0.8, edgecolor='black')
    p2 = ax.bar(x, tld_counts, width, bottom=root_counts, 
                label='TLD Servers', color='#f39c12', alpha=0.8, edgecolor='black')
    
    bottom = np.array(root_counts) + np.array(tld_counts)
    p3 = ax.bar(x, auth_counts, width, bottom=bottom, 
                label='Authoritative Servers', color='#2ecc71', alpha=0.8, edgecolor='black')
    
    # Customize
    ax.set_xlabel('Domain Name', fontsize=12, fontweight='bold')
    ax.set_ylabel('Number of Servers', fontsize=12, fontweight='bold')
    ax.set_title('DNS Resolution Steps Breakdown (Root → TLD → Authoritative)\nFirst 10 Queries - PCAP_1_H1', 
                 fontsize=14, fontweight='bold', pad=20)
    
    ax.set_xticks(x)
    ax.set_xticklabels(domains, rotation=45, ha='right')
    ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))
    ax.yaxis.grid(True, linestyle='--', alpha=0.7)
    ax.set_axisbelow(True)
    ax.legend(loc='upper right', fontsize=10)
    
    plt.tight_layout()
    
    # Save
    output_path = os.path.join(output_dir, 'h1_resolution_breakdown.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_path}")
    
    try:
        plt.savefig(output_path.replace('.png', '.pdf'), bbox_inches='tight')
    except:
        pass
    plt.close()


def generate_summary_table(queries, stats, output_dir):
    """Generate summary table"""
    print("\nGenerating summary table...")
    
    first_10 = queries[:10]
    
    fig, ax = plt.subplots(figsize=(14, 8))
    ax.axis('tight')
    ax.axis('off')
    
    # Prepare table data
    table_data = [['#', 'Domain', 'Status', 'Latency (ms)', 'Servers', 'Cache']]
    
    for i, query in enumerate(first_10, 1):
        domain = query.get('domain', 'unknown')[:35]
        status = '✓ Success' if query.get('success', False) else '✗ Failed'
        
        # Get latency
        if 'resolution_time_ms' in query:
            latency = f"{query['resolution_time_ms']:.2f}"
        elif 'total_time' in query:
            latency = f"{query['total_time'] * 1000:.2f}"
        else:
            latency = "N/A"
        
        # Get servers count
        if 'resolution_path' in query:
            servers = str(len(query['resolution_path']))
        elif 'steps' in query:
            servers = str(len(query['steps']))
        else:
            servers = "0"
        
        # Get cache status
        cache = query.get('cache_status', 'MISS')
        
        table_data.append([str(i), domain, status, latency, servers, cache])
    
    # Create table
    table = ax.table(cellText=table_data[1:], colLabels=table_data[0],
                    cellLoc='center', loc='center',
                    colWidths=[0.05, 0.35, 0.12, 0.15, 0.1, 0.1])
    
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 2.5)
    
    # Style header
    for i in range(len(table_data[0])):
        table[(0, i)].set_facecolor('#3498db')
        table[(0, i)].set_text_props(weight='bold', color='white')
    
    # Style rows
    for i in range(1, len(table_data)):
        for j in range(len(table_data[0])):
            if i % 2 == 0:
                table[(i, j)].set_facecolor('#ecf0f1')
            
            # Color status column
            if j == 2:
                if '✓' in table_data[i][j]:
                    table[(i, j)].set_facecolor('#d5f4e6')
                else:
                    table[(i, j)].set_facecolor('#fadbd8')
            
            # Color cache column
            if j == 5:
                if table_data[i][j] == 'HIT':
                    table[(i, j)].set_facecolor('#d5f4e6')
    
    plt.title(f'DNS Query Summary - First 10 Queries (PCAP_1_H1)\n' +
              f'Custom DNS Resolver (10.0.0.5) - Total Queries: {stats.get("total_queries", "N/A")}',
              fontsize=14, fontweight='bold', pad=20)
    
    plt.tight_layout()
    
    output_path = os.path.join(output_dir, 'h1_summary_table.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_path}")
    
    try:
        plt.savefig(output_path.replace('.png', '.pdf'), bbox_inches='tight')
    except:
        pass
    plt.close()


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate_visualizations.py <query_logs.json> [output_dir]")
        print("\nExample:")
        print("  python3 generate_visualizations.py /tmp/dns_queries.json")
        print("  python3 generate_visualizations.py /tmp/dns_queries.json ./graphs")
        sys.exit(1)
    
    json_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else './plots'
    
    if not os.path.exists(json_file):
        print(f"Error: JSON file not found: {json_file}")
        sys.exit(1)
    
    os.makedirs(output_dir, exist_ok=True)
    
    print("="*80)
    print("DNS Query Visualization Generator")
    print("For PCAP_1_H1 - Part D of Assignment")
    print("="*80)
    
    # Load data
    queries, stats = load_query_logs(json_file)
    
    if len(queries) < 10:
        print(f"\nWarning: Only {len(queries)} queries found. Need at least 10.")
        if len(queries) == 0:
            print("No queries to visualize")
            sys.exit(1)
    
    # Generate plots
    plot_latency_first_10(queries, output_dir)
    plot_servers_visited_first_10(queries, output_dir)
    plot_resolution_steps_breakdown(queries, output_dir)
    generate_summary_table(queries, stats, output_dir)
    
    print("\n" + "="*80)
    print("✓ All visualizations generated successfully!")
    print(f"✓ Output directory: {output_dir}")
    print("="*80)
    print("\nGenerated files:")
    print("1. h1_latency_first_10_queries.png/pdf - Latency per query (REQUIRED)")
    print("2. h1_servers_visited_first_10_queries.png/pdf - Servers visited (REQUIRED)")
    print("3. h1_resolution_breakdown.png/pdf - Resolution steps breakdown")
    print("4. h1_summary_table.png/pdf - Summary table")
    print("\n✅ These fulfill the Part D visualization requirements!")


if __name__ == '__main__':
    main()