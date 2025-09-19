import hashlib
from lenght_extension_attack import perform_length_extension

def server_mac(key: bytes, message: bytes) -> str:
    return hashlib.sha256(key + message).hexdigest()

if __name__ == "__main__":
    secret_key = b"key"
    original_message = b"secret"
    original_mac = server_mac(secret_key, original_message)
    print("Original MAC (server) :", original_mac)

    extension = b"altered"

    key_len = 3
    forged_msg, forged_mac = perform_length_extension(original_message, original_mac, extension, key_len)
    server_check_mac = server_mac(secret_key, forged_msg)

    ok = (server_check_mac == forged_mac)

    if ok:
        print("SUCCESS!")
    else:
        print("FAILED!")

    print("Forged message :", forged_msg)
    print("Forged mac:", forged_mac)
    print("Server check mac:", server_check_mac)
