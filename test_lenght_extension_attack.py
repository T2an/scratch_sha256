# test_length_extension.py
import hashlib
from lenght_extension_attack import perform_length_extension

def server_mac(key: bytes, message: bytes) -> str:
    """Simule le serveur : retourne sha256(key || message) en hex."""
    return hashlib.sha256(key + message).hexdigest()

if __name__ == "__main__":
    # --- CONFIGURATION DU TEST (tu peux changer ces valeurs) ---
    secret_key = b"Secr3t!"          # la clé "cachée" (l'oracle la connaît)
    original_message = b"comment=hello"   # message connu de l'attaquant
    # Le vrai serveur aurait calculé :
    original_mac = server_mac(secret_key, original_message)
    print("Original MAC (server) :", original_mac)

    # Ce que l'attaquant veut ajouter (exemple)
    extension = b";admin=true"

    # On parcourt un intervalle plausible de longueurs de clé
    found = False
    for guess_key_len in range(1, 65):
        forged_msg, forged_mac = perform_length_extension(original_message, original_mac, extension, guess_key_len)

        # Le serveur vérifierait : sha256(key || forged_msg)
        server_check_mac = server_mac(secret_key, forged_msg)

        ok = (server_check_mac == forged_mac)
        print(f"guess_key_len={guess_key_len:2} forged_mac={forged_mac}   server_check={server_check_mac}   OK={ok}")

        if ok:
            print("\n*** SUCCESS! ***")
            print("Good guess_key_len =", guess_key_len)
            print("Forged message (bytes):", forged_msg)
            print("Forged message (repr):", repr(forged_msg))
            print("Forged mac:", forged_mac)
            found = True
            break

    if not found:
        print("\nAucune longueur de clé testée n'a fonctionné. Vérifie les hypothèses.")
