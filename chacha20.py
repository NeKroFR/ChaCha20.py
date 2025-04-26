"""
ChaCha20 implementation in pure Python.
Based on RFC 8439: https://tools.ietf.org/html/rfc8439
"""

def rotate_left(v, c):
    """
    Rotate a 32-bit unsigned integer left by c bits.
    
    Args:
        v (int): 32-bit unsigned integer to rotate
        c (int): Number of bits to rotate left
        
    Returns:
        int: Resulting 32-bit unsigned integer after rotation
    """
    return ((v << c) & 0xffffffff) | (v >> (32 - c))

def quarter_round(a, b, c, d):
    """
    Apply the ChaCha20 quarter round function to four 32-bit words to provide diffusion.
    
    Args:
        a (int): 32-bit word
        b (int): 32-bit word
        c (int): 32-bit word
        d (int): 32-bit word
        
    Returns:
        tuple: Modified values (a, b, c, d) after applying quarter round
    """
    a = (a + b) & 0xffffffff
    d = rotate_left(d ^ a, 16)
    
    c = (c + d) & 0xffffffff
    b = rotate_left(b ^ c, 12)
    
    a = (a + b) & 0xffffffff
    d = rotate_left(d ^ a, 8)
    
    c = (c + d) & 0xffffffff
    b = rotate_left(b ^ c, 7)
    
    return a, b, c, d

def chacha20_block(key, counter, nonce):
    """
    Generate a 64-byte ChaCha20 keystream block.
    
    Creates a 16-word state matrix, applies 20 rounds of mixing (10 column rounds
    and 10 diagonal rounds), and adds the result to the initial state.
    
    Args:
        key (bytes): 32-byte encryption key
        counter (int): Initial counter value (32-bit integer)
        nonce (bytes): 12-byte nonce (number used once)
        
    Returns:
        bytes: 64-byte keystream block
    """
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] 
    state = constants.copy()
    
    # Add key (8 words - 32 bytes)
    for i in range(8):
        state.append(
            (key[i*4]) |
            (key[i*4 + 1] << 8) |
            (key[i*4 + 2] << 16) |
            (key[i*4 + 3] << 24)
        )

    # Add counter (1 word - 4 bytes)
    state.append(counter & 0xffffffff)

    # Add nonce (3 words - 12 bytes)
    for i in range(3):
        state.append(
            (nonce[i*4]) |
            (nonce[i*4 + 1] << 8) |
            (nonce[i*4 + 2] << 16) |
            (nonce[i*4 + 3] << 24)
        )
    
    
    # Perform 20 rounds (10 column rounds + 10 diagonal rounds)
    working_state = state.copy()
    for _ in range(10):
        # Column round
        working_state[0], working_state[4], working_state[8], working_state[12] = quarter_round(
            working_state[0], working_state[4], working_state[8], working_state[12])
        working_state[1], working_state[5], working_state[9], working_state[13] = quarter_round(
            working_state[1], working_state[5], working_state[9], working_state[13])
        working_state[2], working_state[6], working_state[10], working_state[14] = quarter_round(
            working_state[2], working_state[6], working_state[10], working_state[14])
        working_state[3], working_state[7], working_state[11], working_state[15] = quarter_round(
            working_state[3], working_state[7], working_state[11], working_state[15])
        
        # Diagonal round
        working_state[0], working_state[5], working_state[10], working_state[15] = quarter_round(
            working_state[0], working_state[5], working_state[10], working_state[15])
        working_state[1], working_state[6], working_state[11], working_state[12] = quarter_round(
            working_state[1], working_state[6], working_state[11], working_state[12])
        working_state[2], working_state[7], working_state[8], working_state[13] = quarter_round(
            working_state[2], working_state[7], working_state[8], working_state[13])
        working_state[3], working_state[4], working_state[9], working_state[14] = quarter_round(
            working_state[3], working_state[4], working_state[9], working_state[14])
    
    # Add the working state to the initial state
    for i in range(16):
        working_state[i] = (working_state[i] + state[i]) & 0xffffffff
    
    # Convert the state to bytes
    output = bytearray(64)
    for i in range(16):
        output[i*4] = working_state[i] & 0xFF
        output[i*4 + 1] = (working_state[i] >> 8) & 0xFF
        output[i*4 + 2] = (working_state[i] >> 16) & 0xFF
        output[i*4 + 3] = (working_state[i] >> 24) & 0xFF
    
    return output

def chacha20_encrypt(key, counter, nonce, plaintext):
    """
    Encrypt plaintext using ChaCha20 stream cipher.
    
    Generates a keystream by running the ChaCha20 block function
    with the provided key, counter, and nonce, then XORs the
    keystream with the plaintext to produce ciphertext.
    
    Args:
        key (bytes): 32-byte encryption key
        counter (int): Initial counter value (32-bit integer)
        nonce (bytes): 12-byte nonce (number used once)
        plaintext (bytes): Message to encrypt
    
    Returns:
        bytes: Encrypted ciphertext
        
    Raises:
        ValueError: If key is not 32 bytes or nonce is not 12 bytes
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")
    
    ciphertext = bytearray(len(plaintext))
    
    # Process the plaintext in 64-byte blocks
    for i in range(0, len(plaintext), 64):
        keystream = chacha20_block(key, counter, nonce)
        for j in range(min(64, len(plaintext) - i)):
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j]
        counter = (counter + 1) & 0xFFFFFFFF
    
    return bytes(ciphertext)

def chacha20_decrypt(key, counter, nonce, ciphertext):
    """
    Decrypt ciphertext using ChaCha20 stream cipher.
    
    Since ChaCha20 is a symmetric stream cipher, decryption is
    identical to encryption - we generate the same keystream and
    XOR it with the ciphertext to recover the plaintext.
    
    Args:
        key (bytes): 32-byte encryption key
        counter (int): Initial counter value (32-bit integer)
        nonce (bytes): 12-byte nonce (number used once)
        ciphertext (bytes): Encrypted message
    
    Returns:
        bytes: Decrypted plaintext
        
    Raises:
        ValueError: If key is not 32 bytes or nonce is not 12 bytes
    """
    return chacha20_encrypt(key, counter, nonce, ciphertext)
