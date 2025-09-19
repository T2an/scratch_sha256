
# Initial hash values (first 32 bits of the fractional parts of sqrt(primes 2..19))
H = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
]

# Round constants (first 32 bits of the fractional parts of cbrt(primes 2..311))
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



def sha256_pad(message_bytes):
    """
    SHA-256 works on blocks of 512 bits (64 bytes). To process messages of unknown length,
    we must add a padding to them so that their total length is a multiple of 512 bits.

    The padding steps are the following:

    1. Append a '1' bit (0x80).
    2. Append '0' bits (0x00) until the message length in bits is congruent to 448 mod 512.
    3. Append the length of the original message (before padding) as a 64-bit big-endian integer.

    The final padded message before hashing should be like this:

    | Original Message | 0x80 | 0x00 .... 0x00 | Length of Original Message |
    |     n bits       |      | <padding bits> |          <64 bits>         |     
    |<---------------------------- 512 bits ------------------------------>|
    """
    original_len_bits = len(message_bytes) * 8
    
    padded = message_bytes + b'\x80'
    
    while (len(padded) * 8) % 512 != 448:
        padded += b'\x00'
    
    padded += original_len_bits.to_bytes(8, byteorder='big')
    
    return padded


def sha256_split_blocks(padded_message):
    """
    SHA-256 works on blocks of 512 bits (64 bytes). To process messages of unknown length,
    we must split the padded message into 512-bit (64-byte) blocks. If the message is not 
    a multiple of 512 bits,we must add a padding to the last block thanks to the sha256_pad 
    function.
    """
    blocks = []
    for i in range(0, len(padded_message), 64):
        blocks.append(padded_message[i:i+64])
    return blocks


def sha256_block_to_words(block):
    """
    sha256 works on words of 32 bits. By work, it means that every operation 
    (rotation, addition, XOR, etc.) is performed on 32-bit integers. This function 
    converts a 64-byte block into 16 words (32-bit integers).

    |  Word 0  |  Word 1  |  ......  |  Word 14  |  Word 15  |
    | 32 bits  | 32 bits  |          |  32 bits  |  32 bits  |
    |<--------------------- 512 bits ----------------------->|

    """
    words = []
    for i in range(0, 64, 4): 
        word = int.from_bytes(block[i:i+4], byteorder='big')
        words.append(word)
    return words

def right_rotate(value, bits):
    """Rotate right a 32-bit integer by 'bits' positions."""
    return ((value >> bits) | (value << (32 - bits))) & 0xFFFFFFFF


def sha256_expand_words(words16):
    """
    Expand 16 words (32-bit) into 64 words using SHA-256 schedule.
    
    W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]  (mod 2^32)
    """
    words = words16[:] 
    for t in range(16, 64):
        s0 = (right_rotate(words[t-15], 7) ^
              right_rotate(words[t-15], 18) ^
              (words[t-15] >> 3))
        s1 = (right_rotate(words[t-2], 17) ^
              right_rotate(words[t-2], 19) ^
              (words[t-2] >> 10))
        new_word = (words[t-16] + s0 + words[t-7] + s1) & 0xFFFFFFFF
        words.append(new_word)
    return words


def sha256_compress(block, H):
    """Compression SHA-256 d'un bloc de 512 bits sur l'état H."""
    # Convertir bloc en mots et les étendre
    W = sha256_expand_words(sha256_block_to_words(block))

    # Initialiser les registres avec les valeurs H
    a, b, c, d, e, f, g, h = H

    # Les fonctions Σ, Ch, Maj
    def big_sigma0(x):
        return right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22)

    def big_sigma1(x):
        return right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25)

    def Ch(x, y, z):
        return (x & y) ^ (~x & z)

    def Maj(x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    # 64 rounds
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

    # Mise à jour de H
    new_H = [
        (H[0] + a) & 0xFFFFFFFF,
        (H[1] + b) & 0xFFFFFFFF,
        (H[2] + c) & 0xFFFFFFFF,
        (H[3] + d) & 0xFFFFFFFF,
        (H[4] + e) & 0xFFFFFFFF,
        (H[5] + f) & 0xFFFFFFFF,
        (H[6] + g) & 0xFFFFFFFF,
        (H[7] + h) & 0xFFFFFFFF,
    ]

    return new_H

def sha256(message_bytes):
    """
    Compute SHA-256 digest for message_bytes (bytes) using the functions implemented above.
    Returns the digest as a hex string (lowercase).
    """
    # 1) Pad
    padded = sha256_pad(message_bytes)

    # 2) Split into 512-bit blocks
    blocks = sha256_split_blocks(padded)

    # 3) Initialize H (copy to avoid mutating global H)
    H_state = H[:]  # H defined earlier in your file

    # 4) Process each block
    for block in blocks:
        H_state = sha256_compress(block, H_state)

    # 5) Produce final digest: concatenate H_state words as big-endian 32-bit words
    digest_bytes = b''.join(h.to_bytes(4, byteorder='big') for h in H_state)
    return digest_bytes.hex()

