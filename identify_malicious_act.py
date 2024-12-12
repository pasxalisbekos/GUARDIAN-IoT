import os
import re
import json
import sys
import csv
import glob
import pandas as pd
import pickle
import joblib
import requests
from collections import defaultdict
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime   
import time 
import tkinter as tk
from tkinter import ttk
from tqdm import tqdm

feature_mapping = {
    'flow_duration': 'Flow Duration',
    'total_fwd_packets': 'Tot Fwd Pkts',
    'total_bwd_packets': 'Tot Bwd Pkts',
    'total_length_of_fwd_packets': 'TotLen Fwd Pkts',
    'total_length_of_bwd_packets': 'TotLen Bwd Pkts',
    'fwd_packet_length_max': 'Fwd Pkt Len Max',
    'fwd_packet_length_min': 'Fwd Pkt Len Min',
    'fwd_packet_length_mean': 'Fwd Pkt Len Mean',
    'fwd_packet_length_std': 'Fwd Pkt Len Std',
    'bwd_packet_length_max': 'Bwd Pkt Len Max',
    'bwd_packet_length_min': 'Bwd Pkt Len Min',
    'bwd_packet_length_mean': 'Bwd Pkt Len Mean',
    'bwd_packet_length_std': 'Bwd Pkt Len Std',
    'flow_bytes_per_sec': 'Flow Byts/s',
    'flow_packets_per_sec': 'Flow Pkts/s',
    'flow_iat_mean': 'Flow IAT Mean',
    'flow_iat_std': 'Flow IAT Std',
    'flow_iat_max': 'Flow IAT Max',
    'flow_iat_min': 'Flow IAT Min',
    'fwd_iat_total': 'Fwd IAT Tot',
    'fwd_iat_mean': 'Fwd IAT Mean',
    'fwd_iat_std': 'Fwd IAT Std',
    'fwd_iat_max': 'Fwd IAT Max',
    'fwd_iat_min': 'Fwd IAT Min',
    'bwd_iat_total': 'Bwd IAT Tot',
    'bwd_iat_mean': 'Bwd IAT Mean',
    'bwd_iat_std': 'Bwd IAT Std',
    'bwd_iat_max': 'Bwd IAT Max',
    'bwd_iat_min': 'Bwd IAT Min',
    'fwd_psh_flags': 'Fwd PSH Flags',
    'bwd_psh_flags': 'Bwd PSH Flags',
    'fwd_urg_flags': 'Fwd URG Flags',
    'bwd_urg_flags': 'Bwd URG Flags',
    'fwd_header_length': 'Fwd Header Len',
    'bwd_header_length': 'Bwd Header Len',
    'fwd_packets_per_sec': 'Fwd Pkts/s',
    'bwd_packets_per_sec': 'Bwd Pkts/s',
    'packet_length_min': 'Pkt Len Min',
    'packet_length_max': 'Pkt Len Max',
    'packet_length_mean': 'Pkt Len Mean',
    'packet_length_std': 'Pkt Len Std',
    'packet_length_variance': 'Pkt Len Var',
    'fin_flag_count': 'FIN Flag Cnt',
    'syn_flag_count': 'SYN Flag Cnt',
    'rst_flag_count': 'RST Flag Cnt',
    'psh_flag_count': 'PSH Flag Cnt',
    'ack_flag_count': 'ACK Flag Cnt',
    'urg_flag_count': 'URG Flag Cnt',
    'cwr_flag_count': 'CWE Flag Count',
    'ece_flag_count': 'ECE Flag Cnt',
    'down_up_ratio': 'Down/Up Ratio',
    'average_packet_size': 'Pkt Size Avg',
    'fwd_segment_size_avg': 'Fwd Seg Size Avg',
    'bwd_segment_size_avg': 'Bwd Seg Size Avg',
    'fwd_bulk_size_avg': 'Fwd Byts/b Avg',
    'fwd_bulk_packet_avg': 'Fwd Pkts/b Avg',
    'fwd_bulk_rate_avg': 'Fwd Blk Rate Avg',
    'bwd_bulk_size_avg': 'Bwd Byts/b Avg',
    'bwd_bulk_packet_avg': 'Bwd Pkts/b Avg',
    'bwd_bulk_rate_avg': 'Bwd Blk Rate Avg',
    'subflow_fwd_packets': 'Subflow Fwd Pkts',
    'subflow_fwd_bytes': 'Subflow Fwd Byts',
    'subflow_bwd_packets': 'Subflow Bwd Pkts',
    'subflow_bwd_bytes': 'Subflow Bwd Byts',
    'fwd_init_win_bytes': 'Init Fwd Win Byts',
    'bwd_init_win_bytes': 'Init Bwd Win Byts',
    'fwd_act_data_pkts': 'Fwd Act Data Pkts',
    'fwd_seg_size_min': 'Fwd Seg Size Min',
    'active_mean': 'Active Mean',
    'active_std': 'Active Std',
    'active_max': 'Active Max',
    'active_min': 'Active Min',
    'idle_mean': 'Idle Mean',
    'idle_std': 'Idle Std',
    'idle_max': 'Idle Max',
    'idle_min': 'Idle Min'
}



# identify the latest csv based on the UNIX timestamp of the name
def get_latest_flow_file(directory="flow_analysis_results"):
    try:
        files = glob.glob(os.path.join(directory, "*.csv"))
        
        if not files:
            print("[!] No CSV files found in directory")
            return None
            
        timestamp_files = [(int(os.path.splitext(os.path.basename(f))[0]), f) for f in files]
        
        latest_file = max(timestamp_files, key=lambda x: x[0])[1]
        
        print(f"[+] Latest flow file: {latest_file}")
        print(f"[+] Timestamp: {os.path.splitext(os.path.basename(latest_file))[0]}")
        
        return latest_file
        
    except Exception as e:
        print(f"[!] Error finding latest flow file: {str(e)}")
        return None

# mapp extracted flow features to the ones used for training (ie to CICFlowMeter's labels)
def rename_flow_columns(df, feature_mapping):
    try:
        columns_to_rename = {col: feature_mapping[col] for col in df.columns if col in feature_mapping}
        
        df = df.rename(columns=columns_to_rename)
        
        print(f"[+] Successfully renamed {len(columns_to_rename)} columns")
        return df
        
    except Exception as e:
        print(f"[!] Error renaming columns: {str(e)}")
        return df

def process_latest_flow_data(directory="flow_analysis_results", feature_mapping=feature_mapping):
    latest_file = get_latest_flow_file(directory)
    if not latest_file:
        return None
    
    try:
        df = pd.read_csv(latest_file)
        print(f"[+] Read CSV with shape: {df.shape}")
        
        df = rename_flow_columns(df, feature_mapping)
        
        return df
        
    except Exception as e:
        print(f"[!] Error processing flow data: {str(e)}")
        return None


captured_traffic_df = process_latest_flow_data()



# Use pre-trained model for the prediction task. Our beta implementation is using the best performing model
# on the mirai classification (most accurate attack captured when performing domain shift)
def perform_prediction_task(captured_traffic_df):
    # Take only first 100 rows of the dataframe ---> testsing purposes
    captured_traffic_df = captured_traffic_df
    
    flow_ids = captured_traffic_df['flow_id'].copy()
    df_to_analysis = captured_traffic_df.drop(columns=['flow_id'])

    model = joblib.load('Random_Forest_model.pkl')

    analysis_df = df_to_analysis.copy()
    flow_ids = captured_traffic_df['flow_id']
    protocols = flow_ids.str.extract(r'-(TCP|UDP)$')[0]
    analysis_df['Protocol'] = (protocols == 'UDP').astype(int)

    expected_features = model.feature_names_in_
    analysis_df = analysis_df[expected_features]

    assert all(analysis_df.columns == expected_features), "Column mismatch!"

    predictions = model.predict(analysis_df)

    results_df = pd.DataFrame({
        'flow_id': flow_ids,
        'prediction': predictions
    })

    malicious_flows = results_df[results_df['prediction'] == 1]
    # thsi can be removed/ general summary of flows 
    print("\nSummary:")
    print(f"Total flows analyzed: {len(predictions)} (limited to first 100)")
    print(f"Flows classified as malicious: {len(malicious_flows)}")
    print(f"Percentage of malicious flows: {(len(malicious_flows)/len(predictions)*100):.2f}%")

    return malicious_flows



# This is the class that performs the analysis of the malicious IPs. Given that we are using a
# free api that has rate limits on the requests for IP information we limit our analysis on the 
# first 50 suspicious IPs 
class IPAnalyzer:
    def __init__(self):
        self.ip_cache = {}
    
    def extract_ips(self, flow_id):
        parts = flow_id.split('-')[0:2]
        ips = [p.split(':')[0] for p in parts]
        return ips
    
    def get_ip_info(self, ip):
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        
        try:
            # Skip private IP addresses we dont care about local ips
            if ip.startswith(('192.168.', '10.', '172.16.')):
                return None
            
            # delay before request for rate limits
            time.sleep(1.5)  
            
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=10) 
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    result = {
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'as': data.get('as', 'Unknown')
                    }
                    try:
                        dns_name = socket.gethostbyaddr(ip)[0]
                        result['dns'] = dns_name
                    except:
                        result['dns'] = 'No DNS record'
                        
                    self.ip_cache[ip] = result
                    return result
                elif data.get('status') == 'fail' and data.get('message') == 'private range':
                    return None
            
            if response.status_code == 429:  # Too Many Requests error code
                time.sleep(5)  
                return self.get_ip_info(ip) 
                
        except Exception as e:
            print(f"Error getting info for IP {ip}: {str(e)}")
        return None

    def analyze_suspicious_flows(self, malicious_flows):
        
        unique_ips = set()
        ip_flows = defaultdict(list)
        
        for _, row in malicious_flows.iterrows():
            ips = self.extract_ips(row['flow_id'])
            for ip in ips:
                if not ip.startswith(('192.168.', '10.', '172.16.')):
                    unique_ips.add(ip)
                    ip_flows[ip].append(row['flow_id'])
        
        ip_info = {}
        for ip in tqdm(unique_ips, desc="Processing IPs", unit="ip"):
            try:
                info = self.get_ip_info(ip)
                if info:
                    ip_info[ip] = info
                time.sleep(1)  
            except Exception as e:
                print(f"Error processing IP {ip}: {str(e)}")

        rows = []
        for ip in tqdm(unique_ips, desc="Creating rows", unit="row"):
            if ip in ip_info:
                info = ip_info[ip]
                rows.append({
                    'IP Address': ip,
                    'Country': info['country'],
                    'City': info['city'],
                    'ISP': info['isp'],
                    'Organization': info['org'],
                    'AS Number': info['as'],
                    'DNS Name': info['dns'],
                    'Related Flows': len(ip_flows[ip]),
                    'Flow IDs': '; '.join(ip_flows[ip])
                })
        
        return pd.DataFrame(rows)

# captured_traffic_df = process_latest_flow_data()
# malicious_flows = perform_prediction_task(captured_traffic_df)
# analyzer = IPAnalyzer()
# suspicious_ips_df = analyzer.analyze_suspicious_flows(malicious_flows)

def show_flow_details(event):
    selected_item = tree.selection()[0]
    ip_address = tree.item(selected_item)['values'][0]
    
    flow_text.delete(1.0, tk.END)
    row = suspicious_ips_df[suspicious_ips_df['IP Address'] == ip_address].iloc[0]
    
    flow_details = f"IP Address: {ip_address}\n\n"
    flow_details += f"Associated Flow IDs:\n{row['Flow IDs']}\n\n"
    flow_details += f"Additional Details:\n"
    flow_details += f"- Organization: {row['Organization']}\n"
    flow_details += f"- Location: {row['City']}, {row['Country']}\n"
    flow_details += f"- Network: {row['ISP']} ({row['AS Number']})\n"
    flow_details += f"- DNS Name: {row['DNS Name']}\n"
    
    flow_text.insert(tk.END, flow_details)


def show_notification_window(suspicious_ips_df):
    suspicious_ips_df = suspicious_ips_df.head(50)
    root = tk.Tk()

    root.title("[!!] Suspicious IP Analysis Report (Mirai Classification)")
    

    def close_window():
        root.destroy()

    # set a timeout that closes the window after 2 minutes (we dont need multiple instances of the same window)
    root.after(120000, close_window)


    # Window specific params (adjustable on display needs)
    window_width = 1200
    window_height = 800
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    center_x = int(screen_width/2 - window_width/2)
    center_y = int(screen_height/2 - window_height/2)
    root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
    
    main_frame = ttk.Frame(root, padding="10")
    main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    
    ttk.Label(main_frame, text="[!!] SUSPICIOUS IP ANALYSIS REPORT (Mirai Classification)", font=('Helvetica', 16, 'bold'), foreground='red').grid(row=0, column=0, sticky=tk.W)
    
    ttk.Label(main_frame, text=f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", font=('Helvetica', 10)).grid(row=1, column=0, sticky=tk.W)
    # Here we could add additional information about a potentially malicious IP but for beta testing we kept it simple
    # with displaying DNS records and geographical properties 
    tree = ttk.Treeview(main_frame, columns=(
        'IP Address', 'Country', 'City', 'ISP', 
        'Organization', 'AS Number', 'DNS Name', 'Related Flows'
    ), show='headings', height=15)
    
    for col in tree['columns']:
        tree.heading(col, text=col)
        tree.column(col, width=140)
    
    # Adjust scroll parameters (framewise) if the flows are more than default (20)
    y_scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=tree.yview)
    x_scrollbar = ttk.Scrollbar(main_frame, orient=tk.HORIZONTAL, command=tree.xview)
    tree.configure(yscrollcommand=y_scrollbar.set, xscrollcommand=x_scrollbar.set)
    
    tree.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    y_scrollbar.grid(row=2, column=1, sticky=(tk.N, tk.S))
    x_scrollbar.grid(row=3, column=0, sticky=(tk.W, tk.E))
    
    ttk.Label(main_frame, text="Flow Details:", font=('Helvetica', 12, 'bold')).grid(row=4, column=0, sticky=tk.W, pady=(10,5))
    
    flow_text = tk.Text(main_frame, height=10, wrap=tk.WORD)
    flow_text.grid(row=5, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    # add the values to the appropraite columns on the table 
    for index, row in suspicious_ips_df.iterrows():
        tree.insert('', tk.END, values=(
            row['IP Address'],
            row['Country'],
            row['City'],
            row['ISP'],
            row['Organization'],
            row['AS Number'],
            row['DNS Name'],
            row['Related Flows']
        ), tags=('suspicious',))
    
    tree.tag_configure('suspicious', background='#FFE6E6')
    
    tree.bind('<<TreeviewSelect>>', show_flow_details)
    
    main_frame.columnconfigure(0, weight=1)
    main_frame.rowconfigure(2, weight=1)
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    
    # save report also as csv for offline analysis (see : get_malicious_ips.py or block_ips.py)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    suspicious_ips_df.to_csv(f'./suspicious_reports/suspicious_ips_{timestamp}.csv', index=False)
    
    # display window
    root.mainloop()





def main():
    interval = 2 * 60 * 60  # 2 hours interval
    print(f"[+] Starting malicious flow detection system")
    print(f"[+] Analysis will run every {interval//60//60} hours")
    while True:
        try:
            print(f"\n[+] Starting analysis at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            captured_traffic_df = process_latest_flow_data()
            
            if captured_traffic_df is not None:
                malicious_flows = perform_prediction_task(captured_traffic_df)
                analyzer = IPAnalyzer()
                suspicious_ips_df = analyzer.analyze_suspicious_flows(malicious_flows.head(100))
                
                if len(suspicious_ips_df) > 0:
                    print(f"[!] Found {len(suspicious_ips_df)} suspicious IPs. Opening notification window...")
                    show_notification_window(suspicious_ips_df)
                else:
                    print("[+] No suspicious external IPs found in the analysis.")
            
            print(f"[+] Analysis complete. Waiting {interval//60//60} hours until next run...")
            time.sleep(interval)
            
        except KeyboardInterrupt:
            print("\n[+] Stopping malicious flow detection system...")
            break
        except Exception as e:
            print(f"[!] Error during analysis: {str(e)}")
            print("[+] Will retry in 2 hours...")
            time.sleep(interval)

if __name__ == "__main__":

    # Prelim testing: ---> Once (not on an inf loop)
    malicious_flows = perform_prediction_task(captured_traffic_df)
    analyzer = IPAnalyzer()
    suspicious_ips_df = analyzer.analyze_suspicious_flows(malicious_flows.head(100))
    if len(suspicious_ips_df) > 0:
        show_notification_window(suspicious_ips_df)
    else:
        print("No suspicious external IPs found in the analysis.")

    # This is the main workflow with the inf loop and the periodic checks (due to time constrains we could not test it exchaustively)
    # main()