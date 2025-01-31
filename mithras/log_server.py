import socket
import multiprocessing
from loguru import logger
from enum import Enum
import sys
import os


if not os.path.exists(os.path.join(os.path.abspath(os.path.dirname(__file__)), "logs_execution")):
    os.makedirs("logs_execution")
my_logger = logger.bind(name="log_server")
my_logger.remove()
my_logger.add(os.path.join(os.path.abspath(os.path.dirname(__file__)), "logs_execution", "logfile.log"), rotation="10 MB", compression="zip", level='DEBUG')


class TypeServer(Enum):
    COVERAGE = 0
    EXEC = 0

def start_log_server(type: TypeServer, host: str, port: int):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server_socket.bind((host, port))
    except OSError as e:
        my_logger.error(f"Error: {e}")
        return

    server_socket.listen(5)
    while True:
        client_socket, client_address = server_socket.accept()
        while True:
            try:
                message = client_socket.recv(1024)
                if not message:
                    break
                
                if type == TypeServer.COVERAGE:
                    my_logger.debug("Coverage Info: " + message.decode())
                else:
                    my_logger.debug("Exec Output: " + message.decode())
            except ConnectionResetError:
                my_logger.error(f"Connection lost with {client_address}")
                break

        client_socket.close()


def start_log_servers():
    multiprocessing.Process(target=start_log_server, args=(TypeServer.COVERAGE, '0.0.0.0', 1234)).start()
    multiprocessing.Process(target=start_log_server, args=(TypeServer.EXEC, '0.0.0.0', 5678)).start()


if __name__ == "__main__":
    start_log_servers()
    sys.stdin.read()
