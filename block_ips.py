import subprocess
import platform
import os
import sys
import argparse
import ipaddress



###################################################################################################################
#                                                                                                                 #
#               BETA TESTING FOR BLOCKING SUSPICIOUS IPS BASED ON THE IDS REPORT                                  #
#                                                                                                                 #
###################################################################################################################


# TO BLOCK A SPECIFIC IP WE UPDATE THE IP TABLES USING: "iptables -A INPUT -s IP_ADDRESS -j DROP":
# WHERE:
#       -A INPUT: Adds rule to the INPUT chain (incoming traffic)
#       -s IP_ADDRESS: Specifies the source IP to block
#       -j DROP: Tells iptables to discard packets from this IP
def block_ip(ip_address):
    system = platform.system().lower()
    
    try:
        if system == "linux":
            if os.geteuid() != 0:
                raise PermissionError("This script needs root privileges to modify iptables. Please run with sudo.")
            
            cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
            subprocess.run(cmd.split(), check=True)
            print(f"[+] Successfully blocked IP {ip_address} on Linux using iptables")
            
        elif system == "windows":
            rule_name = f"Block_IP_{ip_address.replace('.', '_')}"
            cmd = (f'netsh advfirewall firewall add rule name="{rule_name}" '
                  f'dir=in action=block remoteip={ip_address}')
            subprocess.run(cmd, check=True)
            print(f"[+] Successfully blocked IP {ip_address} on Windows Firewall")
            
        else:
            print(f"[!] Unsupported operating system: {system}")
            
    except subprocess.CalledProcessError as e:
        print(f"[!] Error executing command: {str(e)}")
    except PermissionError as e:
        print(f"[!] Permission error: {str(e)}")
    except Exception as e:
        print(f"[!] Unexpected error: {str(e)}")


#   TO UNBLOCK A SPECIFIC IP WE UPDATE THE IP TABLES USING: "iptables -D INPUT -s IP_ADDRESS -j DROP":
#   WHERE:
#       -D INPUT: Deletes rule from the INPUT chain (incoming traffic)
#       -s IP_ADDRESS: Specifies the source IP to unblock
#       -j DROP: The original drop action we're removing

# The -D flag tells iptables to delete the matching rule instead of adding (-A) one
# The rest of the command must match exactly how the block was originally added
# If the rule isn't found exactly as specified, the unblock will fail
def unblock_ip(ip_address):
    system = platform.system().lower()
    
    try:
        if system == "linux":
            if os.geteuid() != 0:
                raise PermissionError("This script needs root privileges to modify iptables. Please run with sudo.")
            
            cmd = f"iptables -D INPUT -s {ip_address} -j DROP"
            subprocess.run(cmd.split(), check=True)
            print(f"[+] Successfully unblocked IP {ip_address} on Linux")
            
        elif system == "windows":
            rule_name = f"Block_IP_{ip_address.replace('.', '_')}"
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            subprocess.run(cmd, check=True)
            print(f"[+] Successfully unblocked IP {ip_address} on Windows")
            
        else:
            print(f"[!] Unsupported operating system: {system}")
            
    except subprocess.CalledProcessError as e:
        print(f"[!] Error executing command: {str(e)}")
    except PermissionError as e:
        print(f"[!] Permission error: {str(e)}")
    except Exception as e:
        print(f"[!] Unexpected error: {str(e)}")


# verify validity of input IP
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# if __name__ == "__main__":
#     ip_to_block = "192.168.1.100"
#     block_ip(ip_to_block)
#     unblock_ip(ip_to_block)


def main():
    if len(sys.argv) != 3:
        print("Usage:")
        print("For single IP:   python block_ips.py -i <ip_address>")
        print("For IP file:     python block_ips.py -f <filename>")
        sys.exit(1)
    
    flag = sys.argv[1]
    value = sys.argv[2]
    
    if flag == '-i':
        if validate_ip(value):
            print(f"[+] Blocking IP: {value}")
            # block_ip(value)
            # unblock_ip(ip)
        else:
            print(f"[!] Invalid IP address format: {value}")
            exit()
            
    elif flag == '-f':
        try:
            with open(value, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
            
            valid_ips = [ip for ip in ips if validate_ip(ip)]
            
            if not valid_ips:
                print("[!] No valid IP addresses found in file")
                sys.exit(1)
            
            print(f"[+] Found {len(valid_ips)} valid IP addresses to block")
            for ip in valid_ips:
                print(f"[+] Blocking IP: {ip}")
                # block_ip(ip)
                # unblock_ip(ip)

        except FileNotFoundError:
            print(f"[!] Error: File '{value}' not found")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error reading file: {str(e)}")
            sys.exit(1)
            
    else:
        print("[!] Invalid flag. Use -i for single IP or -f for file")
        print("Usage:")
        print("For single IP:   python block_ips.py -i <ip_address>")
        print("For IP file:     python block_ips.py -f <filename>")
        exit()


if __name__ == "__main__":
    main()