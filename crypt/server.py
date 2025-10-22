import socket
from crypt import xor_data

def netcat_server(port, key):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        server_socket.bind(("",port))
        
        server_socket.listen(1)
        print(f"Listening on port {port} ...")

        conn, addr = server_socket.accept()
        print(f"Accepted connection from {addr[0]}:{addr[1]}")

        while True:
            data = conn.recv(4096).decode()
#            if not data:
#                break
            print(f"<<< {data}")

            response = f"{data}"
            conn.sendall(response.encode())

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

    key = input("Please input key: ")

    netcat_server(9090, key)






