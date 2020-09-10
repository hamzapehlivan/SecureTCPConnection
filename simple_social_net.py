# -*- coding: utf-8 -*-
import socket
import sys

# =============================================================================
# CONSTANTS
# =============================================================================
# Protocol
ENCODING = "ascii"
LEN_TYPE = 8
LEN_SIZE = 4

# Encryption
LEN_KEY = 8
LEN_SIGN = 8
LEN_ENCRYPTED = 128

PK_SERVER = (83639845798344785).to_bytes(LEN_KEY, byteorder="big")
SK_SERVER = (-83639845798344785).to_bytes(LEN_KEY, byteorder="big", signed=True)
PK_CA = (298346582736458).to_bytes(LEN_KEY, byteorder="big")

SIGNATURE = (398098863475112337).to_bytes(LEN_SIGN, byteorder="big")
FAKE_SIGNATURE = (1029382974657834).to_bytes(LEN_SIGN, byteorder="big")

# Certificates
CERT_FIELDS = ["NAME", "PK", "CA", "SIGNATURE"]
CERT_BASE = "NAME=www.pa2.com".encode(ENCODING)
CERT_BASE += "PK=".encode(ENCODING) + PK_SERVER
CERT_BASE += "CA=Bilkent CS".encode(ENCODING)
CERT_BASE += "SIGNATURE=".encode(ENCODING)

CERT_FAKE = CERT_BASE + FAKE_SIGNATURE
CERT_TRUE = CERT_BASE + SIGNATURE

# Authentication
USER = "bilkent"
PASS = "cs421"

# Connection
IP = "127.0.0.1"
PORT = int(sys.argv[1])

# Other
PUBLIC_POST = """Alice: Today is my birthday! -- 10:13 AM
Bob: Happy birthday Alice! -- 12:59 PM"""

PRIVATE_MESSAGES = "Your inbox is empty. :("

# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================
class ServerShutdownException(Exception):
    pass

# =============================================================================
# FUNCTIONS
# =============================================================================
def send_packet(s, message_type, data="", secret=None):
    # Pad
    message_type += "".join(["x" for _ in range(LEN_TYPE - len(message_type))])

    # Encode type
    message_type = message_type.encode(ENCODING)
    
    # Encrypt with symmetric encryption if secret is given
    if secret:
        data = encrypt_symmetric(data, secret)
    
    # Get data size
    message_size = len(data).to_bytes(LEN_SIZE, byteorder="big")
    
    # Encode data
    if isinstance(data, str):
        data = data.encode(ENCODING)
    
    s.sendall(message_type + message_size + data)
    
    
def receive_packet(s, secret=None):
    message_type = s.recv(LEN_TYPE).decode(ENCODING).strip("x")
    message_size = int.from_bytes(s.recv(LEN_SIZE), byteorder="big")
    data = s.recv(message_size)
    
    # Decrypt if secret is given
    if secret:
        data = decrypt_symmetric(data, secret)
    
    return message_type, data


def shutdown(err=""):
    print("Server is shutting down because of the following error:")
    print(err)
    raise ServerShutdownException
    
    
def check_message_type(expected, received):
    if received != expected:
        shutdown(f"Expecting {expected}, received: {received}")
    
    
def receive_and_check(s, expected, secret=None):
    received, data = receive_packet(s, secret)
    check_message_type(expected, received)
    return data


def check_auth(auth):
    user, psw = auth.decode(ENCODING).split(" ")
    if user == USER and psw == PASS:
        return True
    else:
        return False


def decrypt_asymmetric(ct, sk):
    pk = -int.from_bytes(sk, byteorder="big", signed=True)
    return int.from_bytes(ct, byteorder="big") - pk


def encrypt_symmetric(data, secret):
    if isinstance(data, str):
        data = data.encode(ENCODING)
    data = int.from_bytes(data, byteorder="big")
    return (data * secret).to_bytes(LEN_ENCRYPTED, byteorder="big")


def decrypt_symmetric(ct, secret):
    pt = (int.from_bytes(ct, byteorder="big") // secret)
    return pt.to_bytes((pt.bit_length() + 7) // 8, byteorder='big')



# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    # Create socket
    welcome_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    welcome_sock.bind((IP, PORT))
    
    try:
        # In the first attempt, imitate an attacker by sending a fake signature.
        # In the seconds attempt send the correct signature.
        for attempt in range(2):
            # Listen from the control port
            welcome_sock.listen(1)
            s, addr = welcome_sock.accept()
            print("Client connected.")
            
            ### HANDSHAKE
            # Receive hello
            receive_and_check(s, "HELLO")
                
            # Send hello & fake certificate
            send_packet(s, "HELLO", CERT_FAKE if attempt == 0 else CERT_TRUE)

        
        # Receive secret
        data = receive_and_check(s, "SECRET")
        
        # Decode secret
        secret = decrypt_asymmetric(data, SK_SERVER)
        print("Decoded secret:", secret)
        
        ### AUTHENTICATION
        # Receive encryption start signal
        receive_and_check(s, "STARTENC")    
        
        # Receive authentication & decrypt
        data = receive_and_check(s, "AUTH", secret)
        
        # Correct user & pass
        if check_auth(data):
            send_packet(s, "RESPONSE", "OK", secret)
        
        # Wrong user & pass
        else:
            send_packet(s, "RESPONSE", "Invalid", secret)
            shutdown(f"Wrong username or pass: {data.decode(ENCODING)}. Please check your code.")
            
        # Receive encryption start signal
        receive_and_check(s, "ENDENC")
        
        ### SEND PUBLIC POSTS
        # Receive view request
        receive_and_check(s, "PUBLIC")
        
        # Send the content
        send_packet(s, "RESPONSE", PUBLIC_POST)
        
        ### SEND PRIVATE MESSAGES
        # Receive encryption start signal
        receive_and_check(s, "STARTENC")
        
        # Receive view request
        data = receive_and_check(s, "PRIVATE")
        
        # Send content
        send_packet(s, "RESPONSE", PRIVATE_MESSAGES, secret)
        
        # Receive encryption start signal
        receive_and_check(s, "ENDENC")
        
        ### RECEIVE LOG OUT
        receive_and_check(s, "LOGOUT")
        print("Client logged out.")
            
        
    except ServerShutdownException:
        pass
            
    finally:
        s.close()
        welcome_sock.close()
            