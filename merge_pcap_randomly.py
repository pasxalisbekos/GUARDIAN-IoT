from scapy.all import rdpcap, wrpcap, PcapReader, PcapWriter, Packet
import random
import tempfile
import os
from typing import List, Optional
import time

#####################################################################################################################
#   This is just a beta-testing utility merging both benign and malicious traffic pcaps to be used for testing      # 
#   It is sequential so merging all traffic from a dataset will take O(N) time where N is 100s of GB of packets     #
#####################################################################################################################from scapy.all import rdpcap, wrpcap, PcapReader, PcapWriter, Packet

def merge_and_randomize_large_pcaps(file1: str, file2: str, output_file: str, packets_per_file: int = 200000, chunk_size: int = 10000):
    def read_limited_packets(filename: str, limit: int, chunk_size: int) -> List[Packet]:
        packets = []
        packets_read = 0
        
        with PcapReader(filename) as pcap_reader:
            while packets_read < limit:
                current_chunk_size = min(chunk_size, limit - packets_read)
                chunk = []
                
                try:
                    for _ in range(current_chunk_size):
                        pkt = pcap_reader.read_packet()
                        if pkt is None:
                            break
                        chunk.append(pkt)
                except EOFError:
                    break
                
                if not chunk:
                    break
                    
                packets.extend(chunk)
                packets_read += len(chunk)
                print(f"    Read {packets_read}/{limit} packets from {filename}")
                
        return packets

    print(f"[+] Reading {packets_per_file} packets from each file...")
    start_time = time.time()
    
    # Read limited packets from each file
    file1_packets = read_limited_packets(file1, packets_per_file, chunk_size)
    file2_packets = read_limited_packets(file2, packets_per_file, chunk_size)
    
    total_packets = len(file1_packets) + len(file2_packets)
    print(f"[+] Got {len(file1_packets)} packets from {file1}")
    print(f"[+] Got {len(file2_packets)} packets from {file2}")
    
    # Combine and shuffle all packets
    print("[+] Merging and randomizing packets...")
    all_packets = file1_packets + file2_packets
    random.shuffle(all_packets)
    
    # Write to output file
    print(f"[+] Writing {len(all_packets)} packets to {output_file}")
    wrpcap(output_file, all_packets)
    
    total_time = time.time() - start_time
    print(f"[+] Complete! Output written to {output_file}")
    print(f"[+] Total processing time: {total_time:.2f} seconds")
    print(f"[+] Average processing speed: {total_packets/total_time:.2f} packets/second")
    print(f"[+] Total packets in output file: {total_packets}")

merge_and_randomize_large_pcaps('benign.pcap', 'Mirai.pcap', 'benign_mirai_limited.pcap')