# -*- coding: utf-8 -*-

import binascii
import re
from typing import BinaryIO
from utils import *
from constantes import rcon
import base64


class AES(object):
    """ 
    # Instruções para a implementação da cifra AES
    aesCypher = AES(mode='ecb', input_type='hex')

    # Teste com chave de 128 bits
    key = '000102030405060708090a0b0c0d0e0f'

    # Cifração dos dados com a chave 
    dataEncrypt = aesCypher.encryption('00112233445566778899aabbccddeeff', key)

    # Decifração dos dados com a mesma chave da cifração
    dataDecrypt = aesCypher.decryption(dataEncrypt, key) 
    """

    def __init__(self, mode, input_type, counter=None):
        self.mode = mode
        self.input = input_type
        self.counter = counter
        self.Nb = 0
        self.Nk = 0
        self.Nr = 0

    def Cipher(self, expandedKey, data):
        # No início da cifra, a entrada é copiada para a matriz de estado.
        # Depois de uma adição inicial da Round Key, a Matriz de Estado é transformada implementando
        # uma função de rodada 10, 12 ou 14 vezes (dependendo do comprimento da chave),
        # com a rodada final ligeiramente diferente das primeiras rodadas Nr -1.
        # A matriz de estado final é então copiada como saída.
        state = AddRoundKey(stateMatrix(data), expandedKey[0])
        for r in range(self.Nr - 1):
            state = SubBytes(state, False)
            state = ShiftRows(state, False)
            state = stateMatrix(''.join(MixColumns(state, False)))
            state = AddRoundKey(state, expandedKey[r + 1])

        state = SubBytes(state, False)
        state = ShiftRows(state, False)
        state = AddRoundKey(state, expandedKey[self.Nr])
        # print(state)
        return revertMatrix(state)

    def InvCipher(self, expandedKey, data):
        state = AddRoundKey(re.findall('.' * 2, data), expandedKey[self.Nr])

        for r in range(self.Nr - 1):
            state = ShiftRows(state, True)
            state = SubBytes(state, True)
            state = AddRoundKey(state, expandedKey[-(r + 2)])
            state = MixColumns(state, True)

        state = ShiftRows(state, True)
        state = SubBytes(state, True)
        state = AddRoundKey(state, expandedKey[0])
        return ''.join(state)

    def ExpandKey(self, key):
        # Pega a chave da cifra e executa uma rotina de expansão de chave para gerar uma programação de chave,
        # gerando assim um total de Nb (Nr + 1) palavras.
        w = ['%08x' % int(x, 16) for x in re.findall('.' * 8, key)]
        i = self.Nk
        while i < self.Nb * (self.Nr + 1):
            temp = w[i - 1]
            if i % self.Nk == 0:
                temp = '%08x' % (SubWord(permuta(temp)) ^
                                 (rcon[i // self.Nk] << 24))
            elif self.Nk > 6 and i % self.Nk == 4:
                temp = '%08x' % SubWord(int(temp, 16))
            w.append('%08x' % (int(w[i - self.Nk], 16) ^ int(temp, 16)))
            i += 1
        return [stateMatrix(''.join(w[x:x + 4])) for x in range(0, len(w), self.Nk)]

    def key_handler(self, key, isInv):
        # Obtém o comprimento da chave e define Nb, Nk de acordo e pede o Nr ao usuário.
        print("\n---------- MENU -----------\n")
        print("1 - 1 Rodada")
        print("2 - 3 Rodadas")
        print("3 - 5 Rodadas")
        print("4 - 9 Rodadas")
        print("5 - 13 Rodadas\n")
        choice = input("Insira o número desejado de rodadas: \n")
        if(choice == '1'):
            self.Nr = 1
        elif(choice == '2'):
            self.Nr = 3
        elif(choice == '3'):
            self.Nr = 5
        elif(choice == '4'):
            self.Nr = 9
        elif(choice == '5'):
            self.Nr = 10
        else:
            raise AssertionError(
                str(choice) + " é uma escolha inválida! Use o menu exibido acima.")
        # chave de 128 bits
        if len(key) == 32:
            self.Nb = 4
            self.Nk = 4
        # chave de 192 bits
        elif len(key) == 48:
            self.Nb = 4
            self.Nk = 6
        # chave de 256 bits
        elif len(key) == 64:
            self.Nb = 4
            self.Nk = 8
        # Gera erro com tamanho de chave inválido
        else:
            raise AssertionError(
                "%s é uma chave inválida'!\n Use uma chave de 128 bits, 192 bits ou 256 bits!" % key)
        # Retorna a chave expandida
        if not isInv:
            return self.ExpandKey(key)
        # Retorna a chave expandida invertida
        if isInv:
            return [re.findall('.' * 2, revertMatrix(x)) for x in self.ExpandKey(key)]

    def aes_main(self, data, key, isInv):
        # Lida com os modos de criptografia e descriptografia
        # Criptografa usando o modo ECB
        if self.mode == 'ecb':
            # Obtém o conjunto de chaves expandidas
            expanded_key = self.key_handler(key, isInv)
            return self.ecb(data, expanded_key, isInv)
        # Criptografa usando o modo CTR
        elif self.mode == 'ctr':
            expanded_key = self.key_handler(key, isInv)
            return self.ctr(data, expanded_key, isInv)
        # Gera erro em modo inválido
        else:
            raise AttributeError(
                "\n\n\t Os modos de operação AES suportados são 'ecb', 'ctr'")

    def encryption(self, data, key):
        # Função principal da criptografia AES
        return self.aes_main(data, key, False)

    def decryption(self, data, key):
        # Função principal da descriptografia AES
        return self.aes_main(data, key, True)

    def ecb(self, data, expanded_key, isInv):
        # Modo ECB:
        # O mais simples dos modos de criptografia é o modo Electronic Codebook (ECB).
        # A mensagem é dividida em blocos e cada bloco é criptografado separadamente.
        # Criptografa dados de string hexadecimais
        if self.input == 'hex':
            if not isInv:
                # print("Dados: ", data, " Chave expandids: ", expanded_key, "\n")
                return self.Cipher(expanded_key, data)
            elif isInv:
                # print("Dados: ", data, " Chave expandids: ", expanded_key, "\n")
                return self.InvCipher(expanded_key, data)
        # Criptografa uma string de texto
        elif self.input == 'text':
            if not isInv:
                return self.Cipher(expanded_key, ''.join('%02x' % x for x in padding(data.encode())))
            elif isInv:
                return str(unpadding(binascii.unhexlify(self.InvCipher(expanded_key, data).encode())))[2:-1]
        # Criptografa um fluxo de dados binários
        elif self.input == 'data':
            if not isInv:
                return b''.join(binascii.unhexlify(self.Cipher(
                    expanded_key, str(binascii.hexlify(x))[2:-1]).encode()) for x in unblock(padding(data)))
            if isInv:
                return b''.join(binascii.unhexlify(self.InvCipher(
                    expanded_key, str(binascii.hexlify(x))[2:-1]).encode()) for x in unblock(padding(data)))
        # Gera erro com entrada inválida
        else:
            raise AttributeError(
                "\n\n\t Os tipos de entrada suportados são 'hex', 'text', 'data'")

    def ctr(self, data, expanded_key, isInv):
        # Modo CTR:
        # o modo CTR utiliza um XOR entre a cifra do counter com a chave
        # e os blocos da mensagem
        if self.counter == None:
            raise AttributeError("Counter não encontrado!")
        if self.input == 'data':
            counter = self.counter
            # Counter precisa ser do tamanho da chave
            if len(counter) != 32:
                raise AttributeError("Counter precisa ser de 128 bits!")
            if not isInv:
                data_blocks = []
                cipher_blocks = []
                encrypted_counters = []
                x = 0
                # Separa o data em blocos do tamanho do counter
                while(len(data) >= len(counter)):
                    encrypted_counter = self.Cipher(expanded_key, counter)
                    encrypted_counter = bytearray(encrypted_counter, "utf8")
                    encrypted_counters.append(encrypted_counter)
                    data_blocks.append(data[:len(counter)])
                    data = data[len(counter)+1:]
                    counter = str(int(counter, 16) +1)
                # Para cada bloco e cada counter cifrado (ate counter + n-1)
                # faz o xor entre o resultado da cifra e o bloco de plaintext
                for block in data_blocks:
                    cipher_block = byte_xor(base64.decodebytes(encrypted_counters[x]), block)
                    cipher_blocks.append(cipher_block)
                    x += 1
                ciphertext = b''.join(cipher_blocks)
                return ciphertext
            elif isInv:
                # Como o CTR é simétrico, basta realizar o mesmo procedimento :)
                return self.ctr(data, expanded_key, False)
