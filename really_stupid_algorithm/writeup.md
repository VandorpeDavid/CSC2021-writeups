# Flag 1

First thing to notice is that the public exponent is not verified, so we can set this to a low value (eg 11). Because the first flag is short, `flag ** 11 < n` so a simple 11th root gives us the flag.

# Flag 2

Once again we can set the exponent to a small value. Because the client key is regenerated each time, the flag gets encrypted with a different key each time. If we have 11 pairs `(ct, n)` (`ct = pow(flag2, 11, n)`) we can recover `pow(flag2, 11)` using the Chinese Remainder Theorem. Calculate the 11th root to find the flag.

# Flag 3

To get flag 3, we need to exploit an issue in the ping/pong mechanism. If we send a `ping` request as payload the following array: `[encryptBytes(b'a' * 199, server_key), flag3_encrypted]` the server will decrypt these, concatenate the result together and re-encrypt it with the client key. When re-encrypting, the first 200 characters are put together in the first block. The first 199 of these are our a's. Guess (bruteforce) the 200th character, encrypt it with the client key and check if the ciphertexts match. If they do, you guessed right and recovered the first byte of the flag. We can repeat this with 198, 197, 196, ... a's to recover the flag byte by byte.


# Flag 4

To solve this we need the previous three flags. Once we have them, we have full control over the first 16 bytes of the XOR stream (see [OFB Mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB)) the dummy secret gets XOR'd with before being RSA encrypted. We also have an oracle telling us if 'CSC' is a substring of the decrypted text. However, the number of requests is limited and a byte-by-byte bruteforce is not possible. Can we solve it bit by bit? It turns out we can. 

There are two ways to do this, and both use a fundamental issue with textbook RSA: malleability. In short, this means that `ct == pow(pt, e, n) <=> ct * pow(pow(2, x), e, n) == pt * pow(2, e)`. We can use this to bitshift the plaintext to the right. We know 4 conecutive bytes in the plaintext and the oracle only checks for 3, so we can use the OFB XOR to make sure 'CSC' is in the plaintext even when shifting by a number of bits that is not a multiple 8.

## Solution 1

This was the originally intended solution, and it is slightly harder than the other solution.

But how do we use this to leak information? Assume we know the value of the most significant `a` bits. We can use the OFB XOR to set these all to zero. We now want to know the value of bit `a+1`. If we have a 2048 bit key, we can bitshift the plaintext so this bit is the 2049th least significant bit. This means that if this bit is a 1, then `pt > n`. Due to the way RSA works, this will scramble our plaintext and 'CSC' will no longer be present in it.\

So we can recover bit `a+1` using the following steps:
1) Make sure the highest `a` bits are 0
2) Set up the OFB stream such that the string 'CSC' will be present after we shift bits in the next step.
3) Shift the plaintext to make sure bit `a+1` is at the correct position.
4) Run the oracle. If the oracle accepts the plaintext, the bit was 0 and we are done.
5) If the oracle rejects the plaintext, repeat step 2 and 4 but this time flip bit `a+1`.
4) Run the oracle. If the oracle accepts the plaintext, the bit was 1 and we are done.
6) If the oracle rejects the plaintext, that means bit `a+2` was 1. Flip it to zero and repeat step 2 and 3.
7) Run the oracle. If the oracle accepts the plaintext, the bit was 0 and we are done. If it rejects the plaintext the bit was 1 and we are done as well.

There is a chance of this process failing, but it is uncommon. If it happens, just rerun the solution script.


## Solution 2

Assume we know the lowest `a` bits of the plaintext (initially `a = 4 * 8 = 32` because we know the lower 4 bytes). We can guess bit `a+1` to be `0`. If we XOR (using the OFB encryption)
bits `a+1` through `a-23` with 'CSC' and shift the plaintext accordingly to make sure those 24 bits align with 3 proper bytes, the oracle will tell us if our guess was correct.

So we can recover bit `a+1` using the following steps:
1) Use XOR to set the last `a` bits of the plaintext to 0 to make sure 'CSC' is not a substring.
2) Guess bit `a+1` is 0. XOR bits `a+1` through `a-23` with 'CSC'.
3) Shift the plaintext so those 24 bits align with 3 bytes. This means shifting by `(- a - 1) mod 8`.
4) Run the oracle. If the oracle accepts the plaintext, our guess was corrent and the bit was 0. If it rejects the plaintext the bit was 1. Repeat from step 1 for the next bit.
