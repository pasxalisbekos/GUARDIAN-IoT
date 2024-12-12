from scapy.all import *
from collections import defaultdict, deque
import time
import statistics
from threading import Timer, Lock
import datetime
import copy
import csv
import os
import numpy as np



# This class is used to extract all information flow identifiers (labels) from actuall traffic
# isntead of storing them and perfroming the offline analysis with CICFlowMeter. We follow the 
# exact same metrics used by the tool to extract features that correspond to the ones used for
# training.
class FlowAnalyzer:
    # for testing we used smaller intervals as we dont see real traffic but replicating it
    # from a pcap file
    def __init__(self, analysis_interval=180):
        self.flows = defaultdict(list)
        self.flow_lock = Lock()
        self.analysis_interval = analysis_interval
        self.last_analysis_time = time.time()
        self.output_dir = "flow_analysis_results"
        self.bulk_threshold = 1000  # Threshold for bulk data transfer (bytes)
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        print(f"[+] Flow Analyzer initialized with {analysis_interval} seconds interval")
        self.schedule_analysis()

    # this is used to create biderictional based flow ids
    def get_flow_id(self, packet):
        if IP in packet and (TCP in packet or UDP in packet):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                proto = 'TCP'
            else:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                proto = 'UDP'
            
            if ip_src < ip_dst or (ip_src == ip_dst and sport < dport):
                flow_id = f"{ip_src}:{sport}-{ip_dst}:{dport}-{proto}"
            else:
                flow_id = f"{ip_dst}:{dport}-{ip_src}:{sport}-{proto}"
            
            return flow_id
        return None

    # decide direction of flows based on the IPs and assign the appropriate flow id
    def is_forward_direction(self, packet, flow_id):
        if IP in packet and (TCP in packet or UDP in packet):
            src_ip = packet[IP].src
            return src_ip == flow_id.split('-')[0].split(':')[0]
        return False


    def extract_packet_features(self, packet):
        features = {
            'timestamp': float(packet.time),
            'length': len(packet),
            'header_length': len(packet[IP]),
            'payload_length': len(packet[IP].payload) if IP in packet else 0
        }
        
        if TCP in packet:
            features.update({
                'flags': {
                    'FIN': packet[TCP].flags.F,
                    'SYN': packet[TCP].flags.S,
                    'RST': packet[TCP].flags.R,
                    'PSH': packet[TCP].flags.P,
                    'ACK': packet[TCP].flags.A,
                    'URG': packet[TCP].flags.U,
                    'CWR': packet[TCP].flags.C,
                    'ECE': packet[TCP].flags.E
                },
                'window_size': packet[TCP].window
            })
        
        return features


    # Based on the implementation of cicflowmeter but on actuall traffic (not pcap files)
    # extract bulk statistics of each network flow for the duration of monitoring
    def calculate_bulk_statistics(self, packets, is_forward):
        bulk_counts = []
        bulk_size = 0
        bulk_packet_count = 0
        bulk_start_time = None
        current_bulk = []
        
        for packet, features in packets:
            payload_size = features['payload_length']
            
            if payload_size > self.bulk_threshold:
                if not bulk_start_time:
                    bulk_start_time = features['timestamp']
                bulk_size += payload_size
                bulk_packet_count += 1
                current_bulk.append(payload_size)
            elif bulk_size > 0:
                if bulk_packet_count > 0:
                    bulk_counts.append({
                        'size': bulk_size,
                        'packet_count': bulk_packet_count,
                        'duration': features['timestamp'] - bulk_start_time,
                        'rate': bulk_size / (features['timestamp'] - bulk_start_time) if features['timestamp'] != bulk_start_time else 0
                    })
                bulk_size = 0
                bulk_packet_count = 0
                bulk_start_time = None
                current_bulk = []
    
        if bulk_size > 0 and bulk_packet_count > 0 and bulk_start_time:
            bulk_counts.append({
                'size': bulk_size,
                'packet_count': bulk_packet_count,
                'duration': packets[-1][1]['timestamp'] - bulk_start_time,
                'rate': bulk_size / (packets[-1][1]['timestamp'] - bulk_start_time) if packets[-1][1]['timestamp'] != bulk_start_time else 0
            })
        
        if not bulk_counts:
            return {
                f'{"fwd" if is_forward else "bwd"}_bulk_rate_avg': 0,
                f'{"fwd" if is_forward else "bwd"}_bulk_packet_avg': 0,
                f'{"fwd" if is_forward else "bwd"}_bulk_size_avg': 0
            }
        
        avg_bulk_rate = statistics.mean(b['rate'] for b in bulk_counts)
        avg_bulk_packets = statistics.mean(b['packet_count'] for b in bulk_counts)
        avg_bulk_size = statistics.mean(b['size'] for b in bulk_counts)
        
        return {
            f'{"fwd" if is_forward else "bwd"}_bulk_rate_avg': avg_bulk_rate,
            f'{"fwd" if is_forward else "bwd"}_bulk_packet_avg': avg_bulk_packets,
            f'{"fwd" if is_forward else "bwd"}_bulk_size_avg': avg_bulk_size
        }

    # feature analysis based on statistics (mean,std,median,total,min/max,length)
    def calculate_flow_features(self, packets, fwd_packets, bwd_packets, flow_id):
        if not packets:
            return {}

        flow_duration = (packets[-1][1]['timestamp'] - packets[0][1]['timestamp'])
        flow_duration_microseconds = flow_duration * 1000000

        all_timestamps = [p[1]['timestamp'] for p in packets]
        fwd_timestamps = [p[1]['timestamp'] for p in fwd_packets]
        bwd_timestamps = [p[1]['timestamp'] for p in bwd_packets]

        flow_iats = np.diff(all_timestamps) if len(all_timestamps) > 1 else [0]
        fwd_iats = np.diff(fwd_timestamps) if len(fwd_timestamps) > 1 else [0]
        bwd_iats = np.diff(bwd_timestamps) if len(bwd_timestamps) > 1 else [0]

        all_lengths = [p[1]['length'] for p in packets]
        fwd_lengths = [p[1]['length'] for p in fwd_packets]
        bwd_lengths = [p[1]['length'] for p in bwd_packets]

        fwd_header_lengths = sum(p[1]['header_length'] for p in fwd_packets)
        bwd_header_lengths = sum(p[1]['header_length'] for p in bwd_packets)

        fwd_bulk_stats = self.calculate_bulk_statistics(fwd_packets, True)
        bwd_bulk_stats = self.calculate_bulk_statistics(bwd_packets, False)

        features = {
            'flow_duration': flow_duration_microseconds,
            'total_fwd_packets': len(fwd_packets),
            'total_bwd_packets': len(bwd_packets),
            'total_length_of_fwd_packets': sum(fwd_lengths),
            'total_length_of_bwd_packets': sum(bwd_lengths),
            
            # Packet length statistics
            'fwd_packet_length_min': min(fwd_lengths) if fwd_lengths else 0,
            'fwd_packet_length_max': max(fwd_lengths) if fwd_lengths else 0,
            'fwd_packet_length_mean': statistics.mean(fwd_lengths) if fwd_lengths else 0,
            'fwd_packet_length_std': statistics.stdev(fwd_lengths) if len(fwd_lengths) > 1 else 0,
            'bwd_packet_length_min': min(bwd_lengths) if bwd_lengths else 0,
            'bwd_packet_length_max': max(bwd_lengths) if bwd_lengths else 0,
            'bwd_packet_length_mean': statistics.mean(bwd_lengths) if bwd_lengths else 0,
            'bwd_packet_length_std': statistics.stdev(bwd_lengths) if len(bwd_lengths) > 1 else 0,
            
            # Flow rates
            'flow_bytes_per_sec': sum(all_lengths) / flow_duration if flow_duration > 0 else 0,
            'flow_packets_per_sec': len(packets) / flow_duration if flow_duration > 0 else 0,
            
            # IAT statistics
            'flow_iat_mean': statistics.mean(flow_iats) if len(flow_iats) > 0 else 0,
            'flow_iat_std': statistics.stdev(flow_iats) if len(flow_iats) > 1 else 0,
            'flow_iat_max': max(flow_iats) if len(flow_iats) > 0 else 0,
            'flow_iat_min': min(flow_iats) if len(flow_iats) > 0 else 0,
            
            'fwd_iat_total': sum(fwd_iats),
            'fwd_iat_mean': statistics.mean(fwd_iats) if len(fwd_iats) > 0 else 0,
            'fwd_iat_std': statistics.stdev(fwd_iats) if len(fwd_iats) > 1 else 0,
            'fwd_iat_max': max(fwd_iats) if len(fwd_iats) > 0 else 0,
            'fwd_iat_min': min(fwd_iats) if len(fwd_iats) > 0 else 0,
            
            'bwd_iat_total': sum(bwd_iats),
            'bwd_iat_mean': statistics.mean(bwd_iats) if len(bwd_iats) > 0 else 0,
            'bwd_iat_std': statistics.stdev(bwd_iats) if len(bwd_iats) > 1 else 0,
            'bwd_iat_max': max(bwd_iats) if len(bwd_iats) > 0 else 0,
            'bwd_iat_min': min(bwd_iats) if len(bwd_iats) > 0 else 0,
        }

        features.update(fwd_bulk_stats)
        features.update(bwd_bulk_stats)

        if TCP in packets[0][0]:
            features.update({
                'fwd_psh_flags': sum(1 for p in fwd_packets if 'flags' in p[1] and p[1]['flags']['PSH']),
                'bwd_psh_flags': sum(1 for p in bwd_packets if 'flags' in p[1] and p[1]['flags']['PSH']),
                'fwd_urg_flags': sum(1 for p in fwd_packets if 'flags' in p[1] and p[1]['flags']['URG']),
                'bwd_urg_flags': sum(1 for p in bwd_packets if 'flags' in p[1] and p[1]['flags']['URG']),
                'fin_flag_count': sum(1 for p in packets if 'flags' in p[1] and p[1]['flags']['FIN']),
                'syn_flag_count': sum(1 for p in packets if 'flags' in p[1] and p[1]['flags']['SYN']),
                'rst_flag_count': sum(1 for p in packets if 'flags' in p[1] and p[1]['flags']['RST']),
                'psh_flag_count': sum(1 for p in packets if 'flags' in p[1] and p[1]['flags']['PSH']),
                'ack_flag_count': sum(1 for p in packets if 'flags' in p[1] and p[1]['flags']['ACK']),
                'urg_flag_count': sum(1 for p in packets if 'flags' in p[1] and p[1]['flags']['URG']),
                'cwr_flag_count': sum(1 for p in packets if 'flags' in p[1] and p[1]['flags']['CWR']),
                'ece_flag_count': sum(1 for p in packets if 'flags' in p[1] and p[1]['flags']['ECE']),
                'fwd_init_win_bytes': packets[0][0][TCP].window if self.is_forward_direction(packets[0][0], flow_id) else 0,
                'bwd_init_win_bytes': packets[0][0][TCP].window if not self.is_forward_direction(packets[0][0], flow_id) else 0,
                'fwd_act_data_pkts': sum(1 for p in fwd_packets if TCP in p[0] and len(p[0][TCP].payload) > 0),
                'fwd_seg_size_min': min(len(p[0][TCP]) for p in fwd_packets) if fwd_packets else 0
            })

        features.update({
            'fwd_header_length': fwd_header_lengths,
            'bwd_header_length': bwd_header_lengths,
            'fwd_packets_per_sec': len(fwd_packets) / flow_duration if flow_duration > 0 else 0,
            'bwd_packets_per_sec': len(bwd_packets) / flow_duration if flow_duration > 0 else 0,
            'packet_length_min': min(all_lengths),
            'packet_length_max': max(all_lengths),
            'packet_length_mean': statistics.mean(all_lengths),
            'packet_length_std': statistics.stdev(all_lengths) if len(all_lengths) > 1 else 0,
            'packet_length_variance': statistics.variance(all_lengths) if len(all_lengths) > 1 else 0,
            'down_up_ratio': len(bwd_packets) / len(fwd_packets) if len(fwd_packets) > 0 else 0,
            'average_packet_size': statistics.mean(all_lengths),
            'fwd_segment_size_avg': statistics.mean(fwd_lengths) if fwd_lengths else 0,
            'bwd_segment_size_avg': statistics.mean(bwd_lengths) if bwd_lengths else 0,
            'subflow_fwd_packets': len(fwd_packets),
            'subflow_fwd_bytes': sum(fwd_lengths),
            'subflow_bwd_packets': len(bwd_packets),
            'subflow_bwd_bytes': sum(bwd_lengths),
        })

        active_times, idle_times = self.calculate_active_idle_times(all_timestamps)
        if active_times:
            features.update({
                'active_min': min(active_times),
                'active_mean': statistics.mean(active_times),
                'active_max': max(active_times),
                'active_std': statistics.stdev(active_times) if len(active_times) > 1 else 0
            })
        if idle_times:
            features.update({
                'idle_min': min(idle_times),
                'idle_mean': statistics.mean(idle_times),
                'idle_max': max(idle_times),
                'idle_std': statistics.stdev(idle_times) if len(idle_times) > 1 else 0
            })

        return features

    def calculate_active_idle_times(self, timestamps, threshold=2.0):
        if len(timestamps) < 2:
            return [], []
        
        active_times = []
        idle_times = []
        current_active_start = timestamps[0]
        last_timestamp = timestamps[0]
        
        for timestamp in timestamps[1:]:
            gap = timestamp - last_timestamp
            if gap > threshold:
                active_times.append(last_timestamp - current_active_start)
                idle_times.append(gap)
                current_active_start = timestamp
            last_timestamp = timestamp
        
        active_times.append(last_timestamp - current_active_start)
        
        return active_times, idle_times

    def analyze_flows(self):
        print(f"\n[+] Starting flow analysis at {datetime.datetime.now()}")
        
        with self.flow_lock:
            flows_to_analyze = copy.deepcopy(self.flows)
        
        print(f"[+] Number of flows detected: {len(flows_to_analyze)}")
        
        results = {}
        for flow_id, packets in flows_to_analyze.items():
            if not packets:
                continue
            
            fwd_packets = [p for p in packets if self.is_forward_direction(p[0], flow_id)]
            bwd_packets = [p for p in packets if not self.is_forward_direction(p[0], flow_id)]
            
            results[flow_id] = self.calculate_flow_features(packets, fwd_packets, bwd_packets, flow_id)
        
        if results:
            self.save_to_csv(results)
        
        print(f"[+] Analysis complete at {datetime.datetime.now()}")
        self.schedule_analysis()

    def save_to_csv(self, results):
        timestamp = int(time.time())
        filename = f"{self.output_dir}/{timestamp}.csv"
        
        all_features = set()
        for flow_features in results.values():
            all_features.update(flow_features.keys())
        
        feature_columns = sorted(list(all_features))
        
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            header = ['flow_id'] + feature_columns
            writer.writerow(header)
            
            for flow_id, features in results.items():
                row = [flow_id] + [features.get(feature, '') for feature in feature_columns]
                writer.writerow(row)
        
        print(f"[+] Analysis results saved to {filename}")

    def schedule_analysis(self):
        print(f"[+] Scheduling next analysis in {self.analysis_interval} seconds")
        Timer(self.analysis_interval, self.analyze_flows).start()
    
    def process_packet(self, packet):
        flow_id = self.get_flow_id(packet)
        if flow_id:
            packet_features = self.extract_packet_features(packet)
            with self.flow_lock:
                self.flows[flow_id].append((packet, packet_features))
                if len(self.flows[flow_id]) == 1:
                    pass

def packet_callback(packet):
    analyzer.process_packet(packet)

analyzer = FlowAnalyzer()

def process_pcap(pcap_file):
    print(f"[+] Starting to process PCAP file: {pcap_file}")
    # while true:
    sniff(offline=pcap_file, prn=packet_callback)
    print(f"[+] Finished processing PCAP file")

def capture_live(interface="eth0"):
    print(f"[+] Starting live capture on interface: {interface}")
    # while true:
    sniff(iface=interface, prn=packet_callback)



if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        process_pcap(sys.argv[1])
    else:
        capture_live()