"""
This is a dummy server that echoes
"""

import socket
import threading

HEADER = 64
PORT = 1337
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")

    connected = True
    while connected:
        msg = conn.recv(2048).decode(FORMAT)
        if len(msg) == 0:
            break
        print(f"msg: '{msg}' ")
        if msg == DISCONNECT_MESSAGE:
            connected = False

        print(f"[{addr}] {msg}")
        conn.send(f"{msg}".encode(FORMAT))


    print(f"[CLLOSED] {addr} left.")
    conn.close()


def start():
    server.listen()
    print(f"[LISTENING] Server is listening on {SERVER}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")


if __name__ == '__main__':
    print("[STARTING] server is starting...")
    start()

