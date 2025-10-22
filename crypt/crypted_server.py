import sys
import socket
from crypt import xor_data
from time import sleep


def netcat_server(port, key):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        server_socket.bind(("",port))
        
        server_socket.listen(1)
        print(f"Listening on port {port} ...")

        conn, addr = server_socket.accept()
        print(f"Accepted connection from {addr[0]}:{addr[1]}")

        while True:
            # print("Receive Start")
            data = conn.recv(4096)
            # print("Data received")
            data = xor_data(data, key.encode())
#            if not data:
#                break
            # print("Data decrypted")
            print(f"<<< {data}")

            response = data
            response = xor_data(response.encode(), key.encode())
            # print("# Data encrypted")
            conn.sendall(response)
            # print("# Data Send")

    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"An error ocurred: {e}")

    finally:
        print("Closing Server ...")
        if 'conn' in locals() and conn:
            conn.close()
        server_socket.close()


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} [key]")
        sys.exit()
    key = sys.argv[1]

    netcat_server(9090, key)






