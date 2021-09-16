# -*- coding: utf-8 -*-
from aes import AES

'''Inicializações'''    
# Teste com chave de 128 bits
key = '000102030405060708090a0b0c0d0e0f'
padvector= '000102030405060708090A0B0C0D0E0F'

# # Abre a imagem e realiza leitura do header e dos dados
img_file = open("artefatos/imagemInicial.ppm", "r+b")
header = img_file.read()[:15]
img_file = open("artefatos/imagemInicial.ppm", "r+b")
img = img_file.read()[16:]
'''Fim das inicializações'''

'''Teste para aes em modo CTR'''
aes = AES(mode='ctr', input_type='data', counter=padvector)
ciphertext = aes.encryption(img, key)
cipherstream = header + ciphertext
print(cipherstream)

# # Cria arquivo de output cifrado
cipher_file = open("artefatos/imagemCifradaCTR.ppm", "w+b")
cipher_file.write(cipherstream)

# Decifra o image data e concatena com o header
deciphertext = aes.decryption(ciphertext, key)
decipherstream = header + deciphertext

# Cria arquivo de output decifrado
decipher_file = open("artefatos/imagemDecifradaCTR.ppm", "w+b")
decipher_file.write(decipherstream)
'''Fim do CTR'''
