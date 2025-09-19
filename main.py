import hashlib
from sha256 import sha256

if __name__ == "__main__":
    original_message = b"keysecret" 
    hashlip_sha256 = hashlib.sha256(original_message).hexdigest()
    homemade_sha256 = sha256(original_message)
    print("Hashlib SHA-256: ", hashlip_sha256)
    print("Homemade SHA-256:", homemade_sha256)
    assert hashlip_sha256 == homemade_sha256, "Les deux hash ne sont pas égaux!"
    print("Les deux hash sont égaux!")
