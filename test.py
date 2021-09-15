# -*- coding: utf-8 -*-
from numpy import byte
from aes import AES
import os
import io
import binascii
from PIL import Image

# Instructions for AES
aes = AES(mode='ecb', input_type='data')
        
# Test vector 128-bit key
key = '000102030405060708090a0b0c0d0e0f'

# Opens image and reads header and data separately
img_file = open("test.ppm", "r+b")
header = img_file.read()[:15]
img_file = open("test.ppm", "r+b")
img = img_file.read()[16:]

# Cyphers image data
cyphertext = aes.encryption(img, key)

# Concat header and cyphered image data
cypherstream = header +  cyphertext

# Create output file containing scrambled image bytes
cypher_file = open("out.ppm", "w+b")
cypher_file.write(cypherstream)

# Decyphers image data
decyphertext = aes.decryption(cyphertext, key)
decypherstream = header + decyphertext

# Create output file containing unscrambled image bytes
decypher_file = open("out2.ppm", "w+b")
decypher_file.write(decypherstream)

