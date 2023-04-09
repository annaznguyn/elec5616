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
        self.verbose = True
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
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = b""
        while len(pkt_len_packed) < struct.calcsize("H"):
            pkt_len_packed += self.conn.recv(struct.calcsize("H") - len(pkt_len_packed))
        pkt_len = struct.unpack("H", pkt_len_packed)[0]
        
        print("Received packet length:", pkt_len)

        if self.shared_secret:
            encrypted_data = self.conn.recv(pkt_len)

            print("Received encrypted data:", encrypted_data)

            # Separate salt from HMAC and data
            data_to_recv, hmac_received = encrypted_data[:-32], encrypted_data[-32:]

            print("Received HMAC:", hmac_received)
            print("Received data:", data_to_recv)

          # Verify HMAC
            hmac_value = hmac.new(self.shared_secret, data_to_recv, hashlib.sha256).digest()
            try:
                if not hmac.compare_digest(hmac_value, hmac_received):
                    raise ValueError("HMAC does not match! Message may have been tampered with.")
            except ValueError as e:
                print(str(e))
                return None

            print("HMAC check passed.")

            # Remove salt from data
            original_msg = data_to_recv[:-8]
            
            cipher = AES.new(self.shared_secret, AES.MODE_OFB, iv=self.shared_iv)
            original_msg = cipher.decrypt(bytes(original_msg))

            print("Decrypted message:", original_msg)

            if self.verbose:
                print()
                print("Receiving message of length: {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original message: {}".format(original_msg))
                print()

        else:
            original_msg = self.conn.recv(pkt_len)

        return original_msg

    def close(self):
        self.conn.close()