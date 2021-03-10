# Sage and pwntools clash.
# Run with env variable PWNLIB_NOTERM=true

from pwn import *
from Crypto.Util.number import *
import json

LOCAL = False

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
server.send(client.readline())

server_key_msg = json.loads(server.readline())
server_key_msg['params']['pub_key'][1] = int(11) # Tamper with public exponent.

client.sendline(json.dumps(server_key_msg))
shared_key_line = client.readline()

flag1enc = json.loads(shared_key_line)['params']['iv']
closeConnection(server)
closeConnection(client)

# If you want to do this in python, the easiest way is probably to binary search for the answer. (pow(flag1enc, 1/11) has rounding errors)
print(long_to_bytes(int(Integer(flag1enc[0]).nth_root(11))))
