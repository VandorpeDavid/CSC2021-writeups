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


# Returns (flag2enc, n), with flag2enc the encrypted flag and n the RSA modulus.
def getEncryptedPair():
	client = connectClient()
	client_key_msg = json.loads(client.readline())

	server = connectServer()
	client_key_msg['params']['pub_key'][1] = int(11) # Tamper with public exponent.
	server.sendline(json.dumps(client_key_msg))

	client.send(server.readline())
	server.send(client.readline())

	x = server.readline()
	flag2enc = json.loads(x)['params']['iv']
	closeConnection(client)
	closeConnection(server)
	return (Integer(flag2enc[0]), Integer(client_key_msg['params']['pub_key'][0]))

encrypted_pairs = [getEncryptedPair() for i in range(11)]

moduli = [pair[1] for pair in encrypted_pairs]
ciphertexts = [pair[0] for pair in encrypted_pairs]

solution = crt(ciphertexts, moduli)
solution = solution.nth_root(11)
print(long_to_bytes(int(solution)))
