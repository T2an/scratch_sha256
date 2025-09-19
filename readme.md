# SHA256 staging

This documentation explains the SHA-256 (Secure Hash Algorithm 256-bit) implementation process step by step.

SHA-256 is a cryptographic hash function that takes an input message of any length and produces a fixed 256-bit (32-byte) hash value. It's part of the SHA-2 family of hash functions and is widely used for digital signatures, message authentication, and other security applications.

As shown in the main.py file, this implementation can be used to generate hash values identical to Python's built-in hashlib.sha256() function. It is made for educational purpose.

[RFC](https://datatracker.ietf.org/doc/html/rfc6234)

## Stage 1: Padding

SHA-256 works on blocks of 512 bits (64 bytes). To process messages of unknown length,
we must add a padding to them so that their total length is a multiple of 512 bits.
The padding steps are the following:
1. Append a '1' bit (0x80).
2. Append '0' bits (0x00) until the message length in bits is congruent to 448 mod 512.
3. Append the length of the original message (before padding) as a 64-bit big-endian integer.

## Stage 2: Split into 512-bit blocks

Each block will be processed independently, so we need to split the padded message into 512-bit (64-byte) blocks.
If the message is not a multiple of 512 bits, we must add a padding to the last block thanks to the sha256_pad function.

## Stage 3: Convert the block into words

Word are 32-bit integers. They are the basic units of SHA-256 computation.
A block is 512 bits, we need to split it into 16 words.


## Stage 4: Setting the initial Hash values and round constants
Before hash compuration begin, we need to set the initial Hash values (H0).

For SHA-256, the initial Hash values (H0) are the first 32 bits of the fractional parts of the square root of the first 8 primes (2, 3, 5, 7, 11, 13, 17, 19).

```python
H0 = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
]
``` 

The other constant to define are the round constants (K).
K is defined as the first 32 bits of the fractional parts of the cube root of the first 64 primes (2,...,311).

``` python
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]
```

## Stage 6: Computation

### For loop

The computation start by a for loop that itarate on the number of blocks. 

### Message schedule
Then the message schedule is the step that expand the words of the block into 64 words. Why
because the SHA-256 iteration is done 64 times for each block, so we need 64 words.

The first 16 words are the words from step 3. Then each words is calculated using the following formula:

``` python
W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]  (mod 2^32)
```
σ0 is the following function:

``` python
σ0(x) = ROTR7(x) XOR ROTR18(x) XOR SHR3(x)
```
σ1 is the following function:
``` python
σ1(x) = ROTR17(x) XOR ROTR19(x) XOR SHR10(x)
```
ROTR is the right rotation function, wich mean every bit of the word is shifted to the right by the number 
of bits specified. The bits that are shifted out are added to the left of the word.

The SHR function also shift the bits to the right by the number of bits specified. But the bits that are 
shifted out are discarded. The first bit of the word are set to 0.

### Initialization of the registers

The registers are initialized with the initial Hash values (H0). They are noted as a, b, c, d, e, f, g, h.

``` python

a = H0[0]
b = H0[1]
c = H0[2]
d = H0[3]
e = H0[4]
f = H0[5]
g = H0[6]
h = H0[7]
```

### Register update

In this loop, the registers are updated 64 times with the following formula:

``` python

for t in range(64):
    T1 = (h + big_sigma1(e) + Ch(e, f, g) + K[t] + W[t]) & 0xFFFFFFFF
    T2 = (big_sigma0(a) + Maj(a, b, c)) & 0xFFFFFFFF

    h = g
    g = f
    f = e
    e = (d + T1) & 0xFFFFFFFF
    d = c
    c = b
    b = a
    a = (T1 + T2) & 0xFFFFFFFF
```

The function big_sigma0 and big_sigma1 are just right rotation functions like we did before

``` python
def big_sigma0(x):
    return right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22)
```

``` python
def big_sigma1(x):
    return right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25)
```

The Ch function stand for choose, it is a function that choose the value of x or z depending on the value of y.

``` python

def Ch(x, y, z):
    return (x & y) ^ (~x & z)
```

The maj function stand for majority, it is a function that choose the bit witch is the most represented at 
at the same position in x, y and z.

``` python

def Maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)
```

I had to mention that i found this video, which is very helpful to understand how sha256 works and particularly the register update. You shoud definitely watch it if you still have questions about the sha256 algorithm.

[SHA-256 video by RedBlockBlue](https://www.youtube.com/watch?v=orIgy2MjqrA)

# Stage 7: Update the Hash values

The Hash values are updated by adding the value of the registers to the initial Hash values.

``` python

H0[i] = H0[i] + a
H0[i+1] = H0[i+1] + b
H0[i+2] = H0[i+2] + c
H0[i+3] = H0[i+3] + d
H0[i+4] = H0[i+4] + e
H0[i+5] = H0[i+5] + f
H0[i+6] = H0[i+6] + g
H0[i+7] = H0[i+7] + h
```

## Stage 8: Produce the final digest

Finally, the digest is produced by concatenating the Hash values as big-endian 32-bit words.
32 bits words are concatenated to form a 256 bits digest. It is returned as a hex string.


# length extension attack staging

Intersting resources about length extension attack:

https://www.cryptologie.net/posts/how-did-length-extension-attacks-made-it-into-sha-2/

https://www.youtube.com/watch?v=orIgy2MjqrA


#TODO