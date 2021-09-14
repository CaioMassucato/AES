# -*- coding: utf-8 -*-
from aes import AES
import os
import io
import base64
import binascii
from PIL import ImageFile, Image
ImageFile.LOAD_TRUNCATED_IMAGES = True
from utils import marker_mapping
from struct import unpack

path = 'test'
extension = '.jpeg'
savepath = 'C:=/Users/Caio Massucato/Downloads/'

# Instructions for my AES implication
aes = AES(mode='ecb', input_type='data')
        
# Test vector 128-bit key
key = '000102030405060708090a0b0c0d0e0f'

# Reads image into list of bytes
img_file = open("test.jpeg", 'r+b')
img = img_file.readlines()
img_file.close()


# Removes header from byte list and converts
# it into a byte stream
bytestream = b''.join(img)
byte_data = bytestream.split(sep=b'\xff\xda')
img_data = byte_data[1].strip(b'\xff\xd9')

# # Encrypts the byte stream
cyphertext = aes.encryption(img_data, key)
cypherstream = byte_data[0] + b'\xff\xda' + cyphertext + b'\xff\xd9'

cypher_img = Image.open(io.BytesIO(cypherstream))
cypher_img.load()
cypher_img.show()
cypher_img.close()

# # Decrypts the byte stream
# plaintext = aes.decryption(bytestream, key)


