import struct
import secrets
import hmac
import hashlib
import os

from Crypto.Cipher import AES
from dh import create_dh_key, calculate_dh_secret
from lib.helpers import appendSalt

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.client = client
        self.server = server
        self.verbose = verbose
        self.shared_secret = None
        self.initiate_session()
        
    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret
        
        # Generate a one-time initialization vector (IV) for AES-OFB
        self.shared_iv = secrets.token_bytes(16)
        
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            
            # Send them our public key
            self.send(my_public_key.to_bytes((my_public_key.bit_length() + 7) // 8, 'big'))
            
            # Receive their public key
            their_public_key = int(self.recv())
            
            # Obtain our shared secret
            self.shared_secret = calculate_dh_secret(their_public_key, my_private_key)
            if self.verbose:
                print("Shared hash: {}".format(self.shared_secret.hex()))

            if self.verbose:
                print("Shared IV: {}".format(self.shared_iv.hex()))
            
    def send(self, data):
        if self.shared_secret:
            # Encrypt the message
            cipher = AES.new(self.shared_secret, AES.MODE_OFB, iv=bytes(self.shared_iv))
            data_to_send = cipher.encrypt(data)

            # Append salt to data
            data_to_send = appendSalt(data_to_send)

            # Generate HMAC
            hmac_value = hmac.new(self.shared_secret, data_to_send, hashlib.sha256).digest()

            # Append HMAC to data
            data_to_send += hmac_value

            if self.verbose:
                print()
                print("Original message : {}".format(data))
                print("Encrypted data: {}".format(repr(data_to_send)))
                print("Sending packet of length: {}".format(len(data_to_send)))
                print()
        else:
            data_to_send = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack("H", len(data_to_send))
        self.conn.sendall(pkt_len)
        self.conn.sendall(data_to_send)

    def recv(self):
        # Receive the length of the incoming packet (as an unsigned two byte int)
        pkt_len = self.conn.recv(2)
        pkt_len = struct.unpack("H", pkt_len)[0]

        # Receive the rest of the packet
        data = b""
        while len(data) < pkt_len:
            packet = self.conn.recv(pkt_len - len(data))
            if not packet:
                return None
            data += packet

        # Extract the HMAC and verify it
        hmac_received = data[-32:]
        data_without_hmac = data[:-32-8]
        print("shared_secret:", type(self.shared_secret), self.shared_secret)
        print("data_without_hmac:", type(data_without_hmac), data_without_hmac)
        hmac_calculated = hmac.new(self.shared_secret, data_without_hmac, hashlib.sha256).digest()
        if hmac_received != hmac_calculated:
            raise ValueError("HMAC validation failed")

        # Decrypt the data and remove the appended salt
        cipher = AES.new(self.shared_secret, AES.MODE_OFB, iv=self.shared_iv)
        decrypted_data = cipher.decrypt(data_without_hmac[:-8])
        decrypted_data = decrypted_data.rstrip(b'\0')

        if self.verbose:
            print()
            print("Received packet of length: {}".format(len(data)))
            print("Decrypted data: {}".format(repr(decrypted_data)))
            print()

        return decrypted_data

    def close(self):
        self.conn.close()