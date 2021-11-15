import socket
import json

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.bind((socket.gethostname(), 1337))
s.listen()
while True:
    conn, addr = s.accept()

    f = conn.makefile()

    while True:
        line = f.readline()
        obj = json.loads(line)

        print(obj)

        if "exit" in obj:
            break

    f.close()
    conn.close()

s.close()