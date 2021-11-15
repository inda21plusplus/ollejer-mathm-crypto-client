import socket
import json
import base64
from getpass import getpass


def send_command(sock, username, password):
    file_path: str = input("Enter filepath: ")
    with open(file_path, "rb") as file:
        file_data = file.read()
        file_base_64 = base64.encodebytes(file_data)
        file_base_64_as_string = file_base_64.decode("utf-8")
    print(file_base_64_as_string)
    # Build json object
    data_set = {"type": "write",
                "id": "0",
                "data": file_base_64_as_string}

    json_dump = json.dumps(data_set)
    json_dump += "\n"  # Server reads until new line
    print("Sending: ", json_dump)
    send_to_server(sock, json_dump)

    print(json_dump)


def login_command() -> (str, str):
    print("Enter Username")
    uname: str = input("Username:  ").strip().lower()
    print("Enter Password")
    pword: str = getpass("Password: ")
    return uname, pword


def send_to_server(client: socket.socket, msg: str, header=64, format="utf-8"):
    message = msg.encode(format)
    client.send(message)

def recv_from_server(socket, f, username, password, format="utf-8"):
    try:
        line = f.readline()
        line = line.replace("\n", "")
        json_data = json.loads(line)
        print("Recieved: ", json_data)
        return json_data
    except OSError as e:
        print("OSError")
        err = e.args[0]
        if err == "timed out":
            print("Timed out, try again later")
        else:  # An actual OSError
            raise e

    except Exception as e: # Other unexpected Error
        raise e


def main():

    address = socket.gethostname()
    port = 1337

    s: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((address, port))
    s.settimeout(2)
    f = s.makefile()

    username: str = ""
    password: str = ""

    running: bool = True
    print("Welcome to XboProd: valid commands include [login, logout, send, help]")
    while running:
        user_input: str = input("> ").strip().lower()
        if user_input == "exit":
            break

        if user_input == "login":
            username, password = login_command()

        if user_input == "logout":
            username = ""
            password = ""

        if user_input == "help":
            print("Welcome to XboProd: valid commands include [login, logout, send]")

        if user_input == "send":
            if not username or not password:
                print("Not logged in, provide credentials...")
                username, password = login_command()
            send_command(s, username, password)

        if user_input == "get":
            if not username or not password:
                print("Not logged in, provide credentials...")
                username, password = login_command()
            response_json = recv_from_server(s, f, username, password)
            if response_json:
                data_string_b64 = response_json["data"]
                data = data_string_b64.encode("utf-8")

                with open("output_file.txt", "wb") as file:
                    file.write(base64.decodebytes(data))

    print("Exiting program")


if __name__ == '__main__':
    main()
