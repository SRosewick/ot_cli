import socket

def listen_udp_ipv6(port):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    
    server_address = ('::', port)
    sock.bind(server_address)
    
    print(f"Listening for UDP data on IPv6 port {port}...")
    
    try:
        while True:
            data, address = sock.recvfrom(4096)
            print(f"Received {len(data)} bytes from {address}: {data.decode('utf-8', errors='ignore')}")
    except KeyboardInterrupt:
        print("\nStopped listening.")
    finally:
        sock.close()

if __name__ == "__main__":
    listen_udp_ipv6(18090)