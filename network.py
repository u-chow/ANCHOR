import sys
import re
import socket
import struct

# ============================================================
# 1. Regular expressions and constants
# ============================================================
PRIVATE_IP_REGEX = re.compile(r"^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)")
IPV4_PATTERN = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
IPV6_PATTERN = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
URL_PREFIX_PATTERN = re.compile(r"^(https?://|udp://|tcp://|ftp://|dns://)", re.IGNORECASE)

# ============================================================
# 2. Helper functions
# ============================================================
def int_to_ip(ip_int):
    """Convert an unsigned 32-bit integer to a dotted IPv4 address."""
    try:
        val = int(ip_int)
        if 0 <= val <= 4294967295:
            return socket.inet_ntoa(struct.pack('!I', val))
    except:
        pass
    return None

def char_expand(text):
    """
    Expand text into uppercase characters separated by spaces.
    For example, 'lowi1' becomes 'L O W I 1'.
    """
    return " ".join(list(str(text).upper()))

def is_ipv6_private(addr):
    """Check the IPv6 prefixes and local-address forms treated as private here."""
    low_addr = addr.lower()
    return low_addr.startswith("fe8") or low_addr.startswith("fe9") or \
           low_addr.startswith("fea") or low_addr.startswith("feb") or \
           low_addr.startswith("fd") or low_addr.startswith("fc") or \
           low_addr == "::1" or low_addr == "::" or low_addr == "0:0:0:0:0:0:0:1"

def get_port_type(port_num):
    """
    Classify a port using this normalizer's configured ranges:
    0: PORT_RESERVED
    1-1023: PORT_SYSTEM
    1024-4999: PORT_USER_CLIENT
    5000-65535: PORT_SERVER_DYNAMIC
    """
    if port_num == 0:
        return "PORT_RESERVED"
    elif 1 <= port_num <= 1023:
        return "PORT_SYSTEM"
    elif 1024 <= port_num <= 4999:
        return "PORT_USER_CLIENT"
    elif 5000 <= port_num <= 65535:
        return "PORT_SERVER_DYNAMIC"
    return "PORT_UNKNOWN"

# ============================================================
# 3. Network normalization with optional raw-to-normalized mapping collection
# ============================================================
def standardize_network_socket(network_socket, mapping_collector=None):
    """
    Convert a network endpoint into seven structured fields:
    <protocol>/<scope>/<address type>/<domain characters or NONE>/
    <address detail>/<port type>/<formatted port>.
    """
    # Return the placeholder representation for missing or empty endpoints.
    if not isinstance(network_socket, str) or not network_socket.strip() or network_socket == "0.0.0.0:0":
        res = "<NONE>/<NONE>/<NONE>/<NONE>/<NONE>/<NONE>/<PORT_00000>"
        if mapping_collector is not None:
            mapping_collector.append((network_socket, res))
        return res

    raw_val = network_socket.lower().strip()
    
    # --- Field 1: Protocol ---
    proto = "TCP"
    if raw_val.startswith("https"): proto = "HTTPS"
    elif raw_val.startswith("http"): proto = "HTTP"
    elif raw_val.startswith("udp"): proto = "UDP"
    elif raw_val.startswith("dns"): proto = "DNS"
    
    clean_host_port = URL_PREFIX_PATTERN.sub("", raw_val).split("/")[0]
    
    # --- Separate the host and port, including bracketed IPv6 addresses. ---
    if "[" in clean_host_port and "]" in clean_host_port:
        addr = clean_host_port.split("]")[0].replace("[", "")
        port_part = clean_host_port.split("]")[-1]
        port_raw = port_part.replace(":", "") if ":" in port_part else "0"
    elif clean_host_port.count(':') > 1:
        addr, port_raw = clean_host_port, "0"
    elif ":" in clean_host_port:
        addr, port_raw = clean_host_port.split(":", 1)
    else:
        addr, port_raw = clean_host_port, "0"

    # Convert integer-encoded IPv4 addresses when possible.
    if addr.isdigit():
        addr = int_to_ip(addr) or addr

    # --- Fields 2-5: Scope, address type, domain label, and address detail ---
    if re.match(IPV4_PATTERN, addr):
        scope = "PRIVATE" if PRIVATE_IP_REGEX.match(addr) else "PUBLIC"
        addr_type = "IPV4"
        addr_label = "NONE"
        full_detail = addr
    elif IPV6_PATTERN.match(addr):
        scope = "PRIVATE" if is_ipv6_private(addr) else "PUBLIC"
        addr_type = "IPV6"
        addr_label = "NONE"
        full_detail = addr
    else:
        scope = "PUBLIC"
        addr_type = "DOMAIN"
        addr_label = char_expand(addr)
        full_detail = addr
        if port_raw == "0":
            proto, port_raw = "HTTPS", "443"

    # --- Fields 6-7: Port category and zero-padded port number ---
    try:
        p_num = int(port_raw)
        port_type = get_port_type(p_num)
        formatted_port = f"PORT_{p_num:05d}"
    except:
        port_type = "PORT_INVALID"
        formatted_port = "PORT_00000"

    # Assemble the normalized representation, including the port category.
    res = f"<{proto}>/<{scope}>/<{addr_type}>/<{addr_label}>/<{full_detail}>/<{port_type}>/<{formatted_port}>"

    # --- Optionally record the raw-to-normalized mapping. ---
    if mapping_collector is not None:
        mapping_collector.append((network_socket, res))

    return res

# ============================================================
# 4. Command-line entry point
# ============================================================
def main():
    import pandas as pd

    if len(sys.argv) < 4:
        print("Usage: python network_norm.py <input_csv> <output_norm_csv> <output_mapping_csv>")
        sys.exit(1)

    input_file, output_norm, output_map = sys.argv[1:4]

    try:
        df = pd.read_csv(input_file)
        target_col = df.columns[1] 
        print(f"[*] 甇???甈?: {target_col}")
        
        mapping_list = []
        unique_sockets = df[target_col].unique()
        mapping_dict = {}
        
        for sock in unique_sockets:
            norm_res = standardize_network_socket(sock, mapping_collector=mapping_list)
            mapping_dict[sock] = norm_res
        
        df['normalized'] = df[target_col].map(mapping_dict)
        df.to_csv(output_norm, index=False)
        
        mapping_df = pd.DataFrame(mapping_list, columns=['raw', 'normalized'])
        mapping_df.to_csv(output_map, index=False)
        
        print(f"[+] ??摰?嚗???靘? {list(mapping_dict.values())[0]}")
        
    except Exception as e:
        print(f"[-] ?潛??航炊: {e}")

if __name__ == "__main__":
    main()
