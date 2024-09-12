import socket
import threading
import argparse
import sys


def start_log_server(rl_agent_address, host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rl_agent_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server_socket.bind((host, port))
    except OSError as e:
        print(f"Error: {e}")
        return

    server_socket.listen(5)

    while True:
        client_socket, client_address = server_socket.accept()
        rl_agent_socket.connect((rl_agent_address, port))
        while True:
            try:
                message = client_socket.recv(1024)
                if not message:
                    break

                rl_agent_socket.sendall(message)
            except ConnectionResetError:
                print(f"Connection lost with {client_address}")
                break

        client_socket.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--rl_agent_address", type=str, help="RL Agent Address", required=True)
    args = parser.parse_args()
    threading.Thread(target=start_log_server, args=(args.r, '0.0.0.0', 1234)).start()
    threading.Thread(target=start_log_server, args=(args.r, '0.0.0.0', 5678)).start()
    sys.stdin.read()
