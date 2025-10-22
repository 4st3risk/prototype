import socket 
from crypt import xor_data

def netcat_client(host, port):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        client_socket.connect((host, port))
        print(f"Connected to {host}:{port}")

        while(True):
            data = input(">>> ")
            client_socket.sendall(data.encode())
            response = client_socket.recv(4096).decode()
            print(f"<<< {response}")

    except socket.error as e:
        print(f"Socket Error: {e}")
    except Exception as e:
        print(f"An Error Ocurred: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":

    netcat_client("192.168.53.9", 9090)


