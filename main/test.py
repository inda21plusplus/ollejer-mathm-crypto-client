
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from base64 import b64decode as b64d
from base64 import b64encode as b64e
import base64

if __name__ == '__main__':
    nonce = b64d("WZpq6LXRqs0li3ICrBbTilswVF5zhCPL")
    key = b64d("D3w+NQbJaBLk+cs9IDP57j4znYK/IFmaA18jsLffuyU=")
    plaintext = b"lite data som e fin"
    a = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    out, tag = a.encrypt_and_digest(plaintext)


    print(nonce)
    print(plaintext)
    print(tag)
    print(b64e(out + tag).decode("utf-8"))


