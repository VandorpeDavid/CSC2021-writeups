from pwn import *
import time
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

client_key_line = client.readline()
print(client_key_line)
client_key = json.loads(client_key_line)['params']['pub_key']
server.send(client_key_line)

server_key_line = server.readline()
server_key = json.loads(server_key_line)['params']['pub_key']
client.send(server_key_line)

shared_key_line = client.readline()
flag3enc = json.loads(shared_key_line)['params']['key'][0]
closeConnection(client) # We got all we need from client.
#server.send(shared_key_line)


server_n = server_key[0]
server_e = server_key[1]
client_n = client_key[0]
client_e = client_key[1]

flag = b""
while True:
    pt1 = b"a" * (200 - 1 - len(flag))
    pt = pow(bytes_to_long(pt1), server_e, server_n)
    msg = {"action": "ping", "params": {"payload": [pt, flag3enc]}}
    msg = json.dumps(msg)
    server.sendline(msg)
    resp = json.loads(server.readline())
    ct = resp['params']['payload'][0]
    nextChar = None
    for i in range(256):
        guess = pt1 + flag + bytes([i])
        if pow(bytes_to_long(guess), client_e, client_n) == ct:
            nextChar = bytes([i])
            break
    assert nextChar is not None
    flag += nextChar
    print(flag)
    if nextChar == b'}':
        closeConnection(server)
        exit()



