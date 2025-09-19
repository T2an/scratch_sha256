from sha256 import sha256_compress, sha256_split_blocks
# -------------------------
# Helpers pour length extension
# -------------------------
def parse_hash_to_state(hash_hex):
    """Convertit un digest SHA-256 hex (64 hex chars) en liste de 8 mots 32-bit (big-endian)."""
    if len(hash_hex) != 64:
        raise ValueError("Hash hex must be 64 hex chars for SHA-256.")
    state = []
    for i in range(0, 64, 8):
        word_hex = hash_hex[i:i+8]
        state.append(int(word_hex, 16))
    return state  # [h0, h1, ..., h7]

def sha256_padding_for_total_length(total_len_bytes):
    """
    Retourne la padding qu'on ajouterait à un message de longueur `total_len_bytes` (en octets)
    selon SHA-256 : commence par 0x80, zéros jusqu'à (len % 64 == 56), puis 8-octets length (bits).
    """
    pad = b'\x80'
    while ((total_len_bytes + len(pad)) % 64) != 56:
        pad += b'\x00'
    pad += (total_len_bytes * 8).to_bytes(8, 'big')
    return pad

def perform_length_extension(original_message: bytes, original_mac_hex: str, extension: bytes, key_len: int):
    """
    Retourne (forged_message_bytes, forged_mac_hex) pour la longueur de clé supposée key_len.
    - original_message : message connu (bytes), tel que MAC = SHA256(key || original_message)
    - original_mac_hex : hexdigest (64 hex chars) de SHA256(key || original_message)
    - extension : bytes à ajouter après le original_message + glue
    - key_len : longueur supposée (en octets) de la clé secrète
    """
    # 1) calculer glue_padding (padding qui aurait été ajouté après key||original_message)
    total_before = key_len + len(original_message)  # bytes traités par le serveur avant le glue
    glue = sha256_padding_for_total_length(total_before)
    # forged message visible (sans la clé)
    forged_message = original_message + glue + extension

    # 2) initialiser l'état interne H à partir du MAC connu
    H_state = parse_hash_to_state(original_mac_hex)

    # 3) Il faut maintenant "continuer" le hash en traitant extension puis la padding finale
    # bytes déjà traités avant l'extension = total_before + len(glue)
    bytes_processed_before_extension = total_before + len(glue)

    # padding finale pour la nouvelle longueur totale (en bytes) : bytes_processed_before_extension + len(extension)
    final_total_len = bytes_processed_before_extension + len(extension)
    final_padding = sha256_padding_for_total_length(final_total_len)

    # Les octets qu'on doit réellement fournir au moteur de compression (après l'état initial) :
    to_process = extension + final_padding

    # Split en blocs 64-octets et appliquer compression en partant de H_state
    blocks = sha256_split_blocks(to_process)
    H = H_state[:]  # état courant à manipuler
    for block in blocks:
        H = sha256_compress(block, H)

    # construire le nouveau MAC hex
    forged_mac = b''.join(h.to_bytes(4, byteorder='big') for h in H).hex()
    return forged_message, forged_mac
