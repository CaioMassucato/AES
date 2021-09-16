# -*- coding: utf-8 -*-
from aes import AES

'''Inicializações'''    
# Teste com chave de 128 bits
key = '000102030405060708090a0b0c0d0e0f'

# # Abre a imagem e realiza leitura do header e dos dados
img_file = open("artefatos/imagemInicial.ppm", "r+b")
header = img_file.read()[:15]
img_file = open("artefatos/imagemInicial.ppm", "r+b")
img = img_file.read()[16:]
'''Fim das inicializações'''

'''Teste para aes em modo ECB'''
# Setting de modo e tipo de dado
aes = AES(mode='ecb', input_type='data')

# # Cifra o image data
ciphertext = aes.encryption(img, key)

# # Concatena header com cifra
cipherstream = header +  ciphertext

# # Cria arquivo de output cifrado
cipher_file = open("artefatos/imagemCifradaECB.ppm", "w+b")
cipher_file.write(cipherstream)

# # Decifra o image data e concatena com o header
deciphertext = aes.decryption(ciphertext, key)
decipherstream = header + deciphertext

# # Cria arquivo de output decifrado
decipher_file = open("artefatos/imagemDecifradaECB.ppm", "w+b")
decipher_file.write(decipherstream)
'''Fim do ECB'''