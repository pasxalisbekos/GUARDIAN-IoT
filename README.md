# CSE 570 Project - Modeling an IDS for Diverse IoT Ecosystems
## Components

### 1. Domain Transfer Training Module
Located in `DOMAIN_TRANSFER_MODULES/`, this component handles:
- Model training across different environments
- Cross-domain testing and validation
- Support for multiple ML models:
  - Random Forest
  - Gradient Boosting
  - Decision Trees
  - KNN
  - Logistic Regression
  - Naive Bayes
  - K-Means

### 2. Real-time Traffic Analysis Module (`ids_testing.py`)
Features:
- Captures live network traffic
- Performs periodic flow extraction
- Generates feature-rich CSV files for analysis
- Configurable capture intervals
- Supports both live capture and PCAP file processing

Usage:
```python
python ids_testing.py file_name
```

Key Parameters:
- `file_name`: For offline analysis provide the pcap file path. Online analysis is by default on interface "eth0" but this can be modified

### 3. Malicious Activity Detection (`identify_malicious_act.py`)
Features:
- Periodic monitoring of flow CSV files
- Feature mapping to CICFlowMeter format
- Real-time classification using pre-trained models
- Alert generation for suspicious traffic
- Geographical and service identification for suspicious IPs

Usage:
```python
python identify_malicious_act.py 
```

### 4. IP Management Module (`block_ips.py`)
Features:
- IP blocking/unblocking via iptables
- Batch processing through IP lists
- Automatic rule management

Usage:
```python
python block_ips.py -i  192.168.1.100
python block_ips.py -f  blacklist.txt
```

## Installation

### Prerequisites
- Python 3.8+
- Linux-based system with iptables
- Root privileges for traffic capture

### Dependencies

Required packages:
- scapy
- pandas
- scikit-learn
- numpy
- requests (for IP geolocation)


## Security Considerations

1. Run with appropriate permissions
2. Regularly update blacklists
3. Monitor system logs
4. Back up iptables rules before modifications
5. Verify model integrity before deployment
