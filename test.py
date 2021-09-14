from matplotlib import image
from aes import AES
import os
import io
import binascii
import PIL.Image as Image

path = 'test'
extension = '.bmp'
# savepath = 'C:\Users\Caio Massucato\Downloads'

# Instructions for my AES implication
aes = AES(mode='ecb', input_type='data')
        
# Test vector 128-bit key
key = '000102030405060708090a0b0c0d0e0f'

# Reads image into list of bytes
img = open("test.png", 'r+b').readlines()

# Opens image
initialImg = Image.open("test.png")
initialImg.show()

# Removes header from byte list and converts
# it into a byte stream
header = img.pop(0)
print(header)
bytestream = b''.join(img)
print(bytestream)

# Encrypts the byte stream
cyphertext = aes.encryption(bytestream, key)

# Decrypts the byte stream
plaintext = aes.decryption(cyphertext, key)



