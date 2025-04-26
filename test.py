from chacha20 import chacha20_encrypt, chacha20_decrypt
import os

def generate_random_bytes(n):
    # Generate n random bytes
    return os.urandom(n)

if __name__ == "__main__":
    key = generate_random_bytes(32)
    nonce = generate_random_bytes(12)
    counter = 42 # because 42 is the answer
    
    original_message = b"Very very secret message"
    print(f"Original message ({len(original_message)} bytes): {original_message.decode()}")
    print("Key (hex):", key.hex())
    print("Nonce (hex):", nonce.hex())
    print("Initial counter:", counter)
    
    print("\n--- Encrypting message ---")
    encrypted = chacha20_encrypt(key, counter, nonce, original_message)
    print("Encrypted (hex):", encrypted.hex())
        
    print("\n--- Decrypting message ---")
    decrypted = chacha20_decrypt(key, counter, nonce, encrypted)
    print("Decrypted:", decrypted.decode())
