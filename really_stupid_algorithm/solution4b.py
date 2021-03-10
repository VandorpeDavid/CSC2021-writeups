from pwn import *
import time
import json
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.strxor import strxor

client_iv = os.environ['FLAG1'].encode()[:16]
server_iv = os.environ['FLAG2'].encode()[:16]
aes_key = os.environ['FLAG3'].encode()

LOCAL = False
# context.log_level = 'debug'

# Copied from challenge source code.
def encrypt(pt, key):
    return pow(pt, key[1], key[0])

def encryptBytes(pt, key):
    return [encrypt(bytes_to_long(pt[i:i+200]), key) for i in range(0, len(pt), 200)]

def sha256(pt):
    h = SHA256.new()
    h.update(pt)
    return h.digest()

def deriveAesKey(key):
    return sha256(key)[:16]

# END copied from challenge source code.

def connectClient():
    if LOCAL:
        return process("./files/client.py")
    else:
        return remote('34.254.72.185', 5555)

def connectServer():
    if LOCAL:
        return process("./files/server.py")
    else:
        return remote('34.254.72.185', 5556)

def closeConnection(r):
	r.sendline('{"action":"quit"}')
	r.close()

client = connectClient()
server = connectServer()

client_key_line = client.readline()
client_key = json.loads(client_key_line)['params']['pub_key']
server.send(client_key_line)

server_key_line = server.readline()
server_key = json.loads(server_key_line)['params']['pub_key']
client.send(server_key_line)

shared_key_line = client.readline()
aes_key_enc = json.loads(shared_key_line)['params']['key']

server_n = server_key[0]
server_e = server_key[1]
client_n = client_key[0]
client_e = client_key[1]
aes_key = deriveAesKey(aes_key)

def setClientXorStream(target):
    assert len(target) == 16
    cipher = AES.new(aes_key, AES.MODE_ECB)
    needed_iv = cipher.decrypt(target)
    altered_server_iv = strxor(needed_iv, client_iv)
    cipher2 = AES.new(aes_key, AES.MODE_OFB, iv=needed_iv)
    t = cipher2.encrypt(bytes(16))
    assert t == bytes(16)
    
    client.sendline(json.dumps({'action': 'shared_key_reply', 'params': {'iv': encryptBytes(altered_server_iv, client_key)}}))

    # Consume the answer
    client.readline()

def setServerXorStream(target):
    assert len(target) == 16
    cipher = AES.new(aes_key, AES.MODE_ECB)
    needed_iv = cipher.decrypt(target)
    altered_client_iv = strxor(needed_iv, server_iv)
    
    server.sendline(json.dumps({'action': 'shared_key', 'params': {'iv': encryptBytes(altered_client_iv, server_key), 'key': aes_key_enc}}))
    
    # Consume the answer
    server.readline()

setClientXorStream(bytes(16))
num_bits = (60+16) * 8
base_shift = len(bin(client_n)) - 2 - num_bits + 1

def oracle(a, flag):
    needle = bytes_to_long(b"CSC")
    mask = long_to_bytes((needle << (a-23)) ^ flag).rjust(16, bytes(1))
    setServerXorStream(mask)
    server.sendline(json.dumps({'action': 'decryption_check', 'params': {}}))
    msg = json.loads(server.readline())
    try:
        secret_enc = msg['params']['secret'][0]
    except:
        print(msg)
        exit()

    shift = (-a-1)%8
    payload = (secret_enc * pow(pow(2, shift, client_n), client_e, client_n)) % client_n

    client.sendline(json.dumps({'action': 'decryption_check_reply', 'params': {'secret': [payload]}}))
    resp = json.loads(client.readline())

    return resp['action'] == 'confirm_receipt'

flag = bytes_to_long(b"}CSC")
for i in range(8*12):
    a = i+32

    bit = None
    if oracle(a, flag):
        bit = 0
    else:
        bit = 1

    flag |= bit << a

    print("Recovered bits", long_to_bytes(flag).hex()[:-8].rjust(12*2, '0'))

flag = long_to_bytes(flag)[:-4] + b'}CSC'

server.sendline(json.dumps({'action': 'confirm_receipt', 'params': {'hash': sha256(flag).hex()}}))
print(json.loads(server.readline())['params']['flag'])
closeConnection(server)
closeConnection(client)
