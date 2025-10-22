import socket 
import sys
from crypt import xor_data

def netcat_client(host, port, key):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        client_socket.connect((host, port))
        print(f"Connected to {host}:{port}")

        while(True):
            data = input(">>> ")
            data = xor_data(data.encode(), key.encode())
            print("Data encrypted")
            client_socket.sendall(data)
            print("Data Send")
            response = client_socket.recv(4096)
            print("Data Received")
            response = xor_data(response, key.encode())
            print("Data Decrypted")
            print(f"<<< {response}\n")

    except socket.error as e:
        print(f"Socket Error: {e}")
    except Exception as e:
        print(f"An Error Ocurred: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} [key]")
        sys.exit()
    key = sys.argv[1]

    netcat_client("192.168.53.11", 9090, key)


