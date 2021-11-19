import socket
import os
import json
from random import randbytes 
import base64
import traceback
from getpass import getpass
from Crypto.Cipher import ChaCha20_Poly1305, ChaCha20
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256, HMAC
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes 
from Crypto.PublicKey import RSA





def write_command(sock, private_key, shared_key):
    file_path: str = input("Enter filepath: ")
    with open(file_path, "rb") as file:
        file_data = file.read()
        file_name = os.path.basename(file.name)

        
        cipher = ChaCha20.new(key=private_key)
        ciphertext = cipher.encrypt(file_data)
        private_nonce = base64.b64encode(cipher.nonce).decode('utf-8')
        b64_encrypted_data = base64.b64encode(ciphertext).decode('utf8')
        d = {
            "nonce": private_nonce,
            "filedata": b64_encrypted_data}
        d2 = json.dumps(d).encode('utf8')
        
        d2 = base64.b64encode(d2).decode('utf-8')
    nonce = base64.b64encode(cipher.nonce).decode('utf-8')
    signature = base64.b64encode(HMAC.new(private_key, msg=file_name.encode('utf8'), digestmod=SHA256).digest()).decode('utf-8')
        

    # Build json object
    data_set = {"type": "write",
                "id": file_name,
                "signature": signature,
                "data": d2}
    
    print(data_set)
    _json = json.dumps(data_set)
    nonce_rfc7539 = get_random_bytes(12)
    cipher = ChaCha20_Poly1305.new(key=shared_key, nonce=nonce_rfc7539)
    encrypt, tag = cipher.encrypt_and_digest(_json.encode('utf-8'))

    shared_nonce = base64.b64encode(cipher.nonce).decode('utf-8')
    shared_ciphertext = base64.b64encode(encrypt + tag).decode('utf-8')
    data = f"{shared_nonce} {shared_ciphertext}"
    data += "\n"  # Server reads until new line

    send_to_server(sock, data)
    

def read(file_name, shared_key, private_key, sock, sockfile):
    d = {"type": "read", "id": file_name}
    _json = json.dumps(d)
    nonce_rfc7539 = get_random_bytes(12)
    cipher = ChaCha20_Poly1305.new(key=shared_key, nonce=nonce_rfc7539)
    encrypt, tag = cipher.encrypt_and_digest(_json.encode('utf-8'))

    shared_nonce = base64.b64encode(cipher.nonce).decode('utf-8')
    shared_ciphertext = base64.b64encode(encrypt + tag).decode('utf-8')
    data = f"{shared_nonce} {shared_ciphertext}"
    data += "\n"  # Server reads until new line

    send_to_server(sock, data)
    data = recv_from_server(sockfile)

    nonce, data = data.split(' ')
    nonce = base64.b64decode(nonce)
    data = base64.b64decode(data)

    cipher = ChaCha20_Poly1305.new(key=shared_key, nonce=nonce) 
    data = cipher.decrypt(data)
    data = data.split(b'\n')[0]
    print(data) 
    data = json.loads(data)

    try:
        data = base64.b64decode(data["data"])
        _json = json.loads(data)
        nonce = base64.b64decode(_json["nonce"])
        encrypted_file_data = base64.b64decode(_json["filedata"])
        cipher = ChaCha20.new(key=private_key, nonce=nonce)
        decrypted_data = cipher.decrypt(encrypted_file_data)
    
        with open("output2.txt", "wb") as file:
            print(0)
            file.write(decrypted_data)

    except (ValueError, KeyError) as e:
        print(f"Incorrect decryption: {e}")


def login_command():
    uname: str = input("Username:  ").strip().lower()
    pword: str = getpass("Password: ")
    return uname, pword


def send_to_server(client: socket.socket, msg: str, format="utf-8"):
    message = msg.encode(format)
    print("Sending: ", msg)
    client.send(message)

def recv_from_server(f):
    try:
        line = f.readline()
        line = line.replace("\n", "")
        return line
    except OSError as e:
        print("OSError")
        err = e.args[0]
        if err == "timed out":
            print("Timed out, try again later")
        else:  # An actual OSError
            raise e

    except Exception as e: # Other unexpected Error
        raise e

def setup_socket(addr: str, port: int, nonblocking = True):
    """Creates a socket. Returns socket and corresponding makefile"""
    s: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((addr, port))
    if nonblocking:
        s.settimeout(5)
    f = s.makefile()
    return s, f


def get_command(s, f, username, password, key):
    response = recv_from_server(f)
    response_json = json.loads(response)
    if response_json:
        try:
            nonce = base64.b64decode(response_json['nonce'])
            encrypted_data = base64.b64decode(response_json["data"])
            cipher = ChaCha20.new(nonce=nonce, key=key)
            decrypted_data = cipher.decrypt(encrypted_data)
            #data = data.encode("utf-8")
            with open("output_file.txt", "wb") as file:
                print(0)
                file.write(decrypted_data)
                print(1)

        except (ValueError, KeyError) as e:
            print(f"Incorrect decryption: {e}")
            

def get_key(b64str):
    pem = base64.b64decode(b64str)
    return RSA.import_key(pem)


def main():
    # Socket
    
    address = socket.gethostbyname(socket.gethostname())
    port = 10000
    sock, sockfile = setup_socket(address, port, nonblocking=False)

    # Key exchange with RSA
    # 0: Load Va and setup keys

    with open('resources/Va.pem', 'r') as file:
        Va = RSA.import_key(file.read())

    with open('resources/Ec.pem', 'r') as file:
        encryption_private_key = RSA.import_key(file.read())
    encryption_public_key = encryption_private_key.public_key()
    Ec = encryption_public_key.export_key(format="PEM")
    Ec = base64.b64encode(Ec).decode("utf-8")

    with open('resources/Vc.pem', 'r') as file:
        signing_private_key = RSA.import_key(file.read())
    signing_public_key = signing_private_key.public_key()
    Vc = signing_public_key.export_key(format="PEM")
    Vc = base64.b64encode(Vc).decode("utf-8")

    # 1: client sends (Ec + Vc)
    # b64(Ec + Vc)
    _json = {'Ec': Ec, 'Vc': Vc}
    Ec_Vc = json.dumps(_json) +  '\n'
    send_to_server(sock, Ec_Vc)

    # 2: server sends Ec(Es + Vs + Sa(Sha256(Es)))
    
    b64_encrypted_data_unsplitted = recv_from_server(sockfile)
    print(f"Server: {b64_encrypted_data_unsplitted}")
    b64_encrypted_data_chunks = b64_encrypted_data_unsplitted.split(",")

    payload = b""
    for (i, chunk) in enumerate(b64_encrypted_data_chunks):
        encrypted_data = base64.b64decode(chunk)
        encryption_cipher_rsa = PKCS1_OAEP.new(encryption_private_key, hashAlgo=SHA256)
        decrypted_data = encryption_cipher_rsa.decrypt(encrypted_data) # Gives {'Es': b64(Es), 'Vs': Vs, 'Sa(Es)': b64(Sa(Es))}
        payload += decrypted_data
    
    try:
        _json = json.loads(payload)
        Es = get_key(_json['Es'])
        Vs = get_key(_json['Vs'])
        # 3: client verifies Es with Sa(Es)
        Va_cipher_rsa = PKCS1_OAEP.new(Va)
        SaEs = _json['Sa(Es)']
        pkcs1_15.new(Va).verify(SHA256.new(base64.b64decode(_json['Es'])), base64.b64decode(SaEs))

    except Exception as e:

        print(e)
        traceback.print_exc()
    
    # 4: client sends Es(16 rand bytes + Sc(sha256(8 rand bytes)) )
    # b64(Ec({"data":b64(data),"sign":b64(Sc(sha256(data)))}))
    random_bytes = randbytes(16)
    data = base64.b64encode(random_bytes).decode('utf8')

    signature = pkcs1_15.new(signing_private_key).sign(SHA256.new(random_bytes))
    signature = base64.b64encode(signature).decode('utf-8')

    _json = json.dumps({"data": data, "sign": signature}) + '\n'
  
    Es_cipher_rsa = PKCS1_OAEP.new(Es, hashAlgo=SHA256)
    payload = ""
    print(len(_json), _json)
    for i in range(0, len(_json), 128):
        end = i + 128
        if end > len(_json):
            end = len(_json)
        
        chunk = bytes(_json[i:end], 'utf-8')
        encrypted_data = Es_cipher_rsa.encrypt(chunk)
        b64_encrypted_data = base64.b64encode(encrypted_data).decode('utf-8')
        if i != 0:
            payload += ","
        payload += b64_encrypted_data

    payload += '\n'

    send_to_server(sock, payload)

    # 5: server sends Ec(8 rand bytes + Ss(sha256(8 rand bytes)))
    try:
        b64_encrypted_data = recv_from_server(sockfile)
        encrypted_data = base64.b64decode(b64_encrypted_data)

        payload = b""
        b64_encrypted_data_chunks = b64_encrypted_data.split(",")
        for (i, chunk) in enumerate(b64_encrypted_data_chunks):
            encrypted_data = base64.b64decode(chunk)
            encryption_cipher_rsa = PKCS1_OAEP.new(encryption_private_key, hashAlgo=SHA256)
            decrypted_data = encryption_cipher_rsa.decrypt(encrypted_data) # Gives {'Es': b64(Es), 'Vs': Vs, 'Sa(Es)': b64(Sa(Es))}
            payload += decrypted_data

        _json = json.loads(payload)


        server_random_bytes = base64.b64decode(_json["data"])
        signature = base64.b64decode(_json["signature"])
        pkcs1_15.new(Vs).verify(SHA256.new(server_random_bytes), signature)

    except Exception as e:
        print(e)

    # 6: (R1+R2) is used for ChaCha128 1337 elite poly 
    
    shared_key = random_bytes + server_random_bytes
    private_key = randbytes(32)

    running: bool = True
    print("Welcome to XboProd: valid commands include [login, logout, send, help]")
    while running:
        user_input: str = input("> ").strip().lower()
        if user_input == "exit":
            break

        if user_input == "list":
            send_to_server(sock, '{"type": "list"}\n')
            bluppfisk = recv_from_server(sockfile)
            print(json.loads(bluppfisk))

        if user_input == "write":
            write_command(sock, private_key, shared_key)
            bluppfisk = recv_from_server(sockfile)
            print(bluppfisk)

        if user_input == "read":
            id = input("Enter id: ")
            read(id, shared_key, private_key, sock, sockfile)
            

    print("Exiting program")

if __name__ == '__main__':
    main()
