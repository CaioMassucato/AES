# -*- coding: utf-8 -*-
from numpy import byte
from aes import AES
import os
import io
import binascii
from PIL import Image

# Setting de modo e tipo de dado
aes = AES(mode='ecb', input_type='data')
        
# Teste com chave de 128 bits
key = '000102030405060708090a0b0c0d0e0f'

# Abre a imagem e realiza leitura do header e dos dados
img_file = open("artefatos/imagemInicial.ppm", "r+b")
header = img_file.read()[:15]
img_file = open("artefatos/imagemInicial.ppm", "r+b")
img = img_file.read()[16:]

# Cifra o image data
cyphertext = aes.encryption(img, key)

# Concatena header com cifra
cypherstream = header +  cyphertext

# Cria arquivo de output cifrado
cypher_file = open("artefatos/imagemCifrada.ppm", "w+b")
cypher_file.write(cypherstream)

# Decifra o image data e concatena com o header
decyphertext = aes.decryption(cyphertext, key)
decypherstream = header + decyphertext

# Cria arquivo de output decifrado
decypher_file = open("artefatos/imagemDecifrada.ppm", "w+b")
decypher_file.write(decypherstream)

