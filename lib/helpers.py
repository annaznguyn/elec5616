import string
from Crypto.Hash import HMAC, SHA256
import secrets

def read_hex(data):
    # Remove any spaces or newlines
    data = data.replace(" ", "").replace("\n", "")
    # Read the value as an integer from base 16 (hex)
    return int(data, 16)

def generate_random_string(alphabet=None, length=8, exact=False):
    if not alphabet:
        alphabet = string.ascii_letters + string.digits

    if not exact:
        min = 1
        max = length + 4
        length = secrets.choice([i for i in range(min, max)])
    return ''.join(secrets.choice(alphabet) for x in range(length))

def appendMac(data, secret):
    ## return data with MAC appended to it.
    h = HMAC.new(secret, digestmod=SHA256)
    h.update(data)
    return data + bytes.fromhex(h.hexdigest())

def macCheck(data, hmac, secret):
    ## return a boolean representing whether the mac is correct or not.
    h = HMAC.new(secret, digestmod=SHA256)
    h.update(data)
    try:
        h.hexverify(hmac.hex())
        return True
    except:
        return False

def appendSalt(data):
    return data + secrets.token_bytes(8)  # We use 8 bytes for the salt - (check!!)
