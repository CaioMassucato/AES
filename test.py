from aes import AES
import os

# Instructions for my AES implication
aes = AES(mode='ecb', input_type='hex')
        
# Test vector 128-bit key
key = '000102030405060708090a0b0c0d0e0f'
    
# Encrypt data with your key
cyphertext = aes.encryption('00112233445566778899aabbccddeeff', key)
cyphertext = aes.decryption('69c4e0d86a7b0430d8cdb78070b4c55a', key)
    
# Decrypt data with the same key
plaintext = aes.decryption(cyphertext, key) 