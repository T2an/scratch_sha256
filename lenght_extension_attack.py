from sha256 import sha256_compress, sha256_split_blocks


def parse_hash_to_state(hash_hex):
    """
    In order to continue the hash, we need to parse the hash to the state
    which is a list of 8 words 32-bit (big-endian).
    """

    if len(hash_hex) != 64:
        raise ValueError("Hash hex must be 64 hex chars for SHA-256.")
    state = []
    for i in range(0, 64, 8):
        word_hex = hash_hex[i:i+8]
        state.append(int(word_hex, 16))
    return state  

def sha256_padding_for_total_length(total_len_bytes):
    """
    We are redefing a padding function that calculates the padding for a total length in bytes 
    in order to perform the length extension attack while only knowing the original message and
    and key length, but not their content.
    """
    pad = b'\x80'
    while ((total_len_bytes + len(pad)) % 64) != 56:
        pad += b'\x00'
    pad += (total_len_bytes * 8).to_bytes(8, 'big')
    return pad

def perform_length_extension(original_message: bytes, original_mac_hex: str, extension: bytes, key_len: int):
    """
    Perform a SHA-256 length-extension attack for a naive MAC of the form SHA256(key || message).
    The required information are :

    - the original message
    - the original MAC
    - the extension
    - key length
 
    it use the fact that SHA-256 is a Merkle-Damgard construction, so we can use the original MAC
    as the initial state of the hash and continue the hash by adding the extension.

    """
    total_before = key_len + len(original_message) 
    glue = sha256_padding_for_total_length(total_before)
    forged_message = original_message + glue + extension

    H_state = parse_hash_to_state(original_mac_hex)

    bytes_processed_before_extension = total_before + len(glue)

    final_total_len = bytes_processed_before_extension + len(extension)
    final_padding = sha256_padding_for_total_length(final_total_len)

    to_process = extension + final_padding

    blocks = sha256_split_blocks(to_process)
    H = H_state[:]
    for block in blocks:
        H = sha256_compress(block, H)

    forged_mac = b''.join(h.to_bytes(4, byteorder='big') for h in H).hex()
    return forged_message, forged_mac
