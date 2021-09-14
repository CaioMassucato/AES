import binascii
import re
import matplotlib.image as mpimg
import matplotlib.pyplot as plt
import numpy

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
    def __init__(self, mode, input_type, iv = None):
        self.mode = mode
        self.input = input_type
        self.iv = iv
        self.Nb = 0
        self.Nk = 0
        self.Nr = 0

        # Rijndael S-box 
        # (caixa de substituição usada na cifra Rijndael, na qual a cifra AES é baseada)
        self.sBox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
            0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
            0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
            0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
            0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
            0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
            0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
            0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
            0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
            0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
            0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
            0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
            0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
            0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
            0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
            0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
            0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
            0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
            0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
            0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
            0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
            0x54, 0xbb, 0x16]

        # Rijndael Inverted S-box
        # (basicamente uma S-box, mas que roda de maneira inversa)
        self.sBoxInverted = [
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
            0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
            0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54,
            0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
            0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
            0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8,
            0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
            0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
            0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab,
            0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
            0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
            0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
            0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
            0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
            0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
            0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
            0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
            0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60,
            0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
            0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
            0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b,
            0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
            0x21, 0x0c, 0x7d]

        # Round constant
        self.rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

    @staticmethod
    def padding(data, block = 16):
    # Método de preenchimento dos dados
    # consiste em inserir dados em uma mensagem antes da cifração 
        if block < 2 or block > 255:
            raise ValueError("Tamanho do bloco deve ser < 2 e > 255")

        if len(data) == block: return data
        padded = block - (len(data) % block)
        return data + binascii.unhexlify(('%02x' % int(padded)).encode()) + b'\x00' * (padded - 1)

    @staticmethod
    def unpadding(data):
    # Retirada de preenchimento dos dados depois do processo de decifração 
        p = None
        for x in data[::-1]:
            if x == 0:
                continue
            elif x != 0:
                p = x; break
        data = data[::-1]
        data = data[p:]
        return data[::-1]

    @staticmethod
    def unblock(data, size = 16):
    # Desbloqueia dados binários
        # Retorna blocos de 64 bits de dados
        return [data[x:x + size] for x in range(0, len(data), size)]

    @staticmethod
    def permuta(word):
    # Seleciona uma palavra [a0, a1, a2, a3] como entrada e executa uma 
    # permutação cíclica que retorna a palavra [a1, a2, a3, a0].
        return int(word[2:] + word[0:2], 16)

    @staticmethod
    def stateMatrix(state):
    # Formata uma matriz de estado str para uma lista formatada.
        newState = []
        split = re.findall('.' * 2, state)
        for x in range(4):
            # lenState = new_state.__len__()
            # print("Len: ", lenState , " X: ", x)
            newState.append(split[0:4][x]); newState.append(split[4:8][x])
            newState.append(split[8:12][x]); newState.append(split[12:16][x])
        return newState

    @staticmethod
    def revertMatrix(state):
    # Inverte o formato da Matriz de Estado como str
        columns = [state[x:x + 4] for x in range(0, 16, 4)]
        return ''.join(''.join([columns[0][x], columns[1][x], columns[2][x], columns[3][x]]) for x in range(4))

    @staticmethod
    def galoisField(a, b):
    # Multiplicação pelo método de Galois de caracteres de 8 bits a e b
        p = 0
        for counter in range(8):
            if b & 1: p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            # mantém os 8 bits
            a &= 0xFF
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p

    @staticmethod
    def AddRoundKey(state, key):
    # Adiciona uma Round Key ao estado usando uma operação XOR.
        return ['%02x' % (int(state[x], 16) ^ int(key[x], 16)) for x in range(16)]

    def ShiftRows(self, state, isInv):
    # Altera o estado, deslocando ciclicamente as últimas 
    # três linhas do estado por diferentes deslocamentos.
        offset = 0
        if isInv: 
            state = re.findall('.' * 2, self.revertMatrix(state))
        for x in range(0, 16, 4):
            state[x:x + 4] = state[x:x + 4][offset:] + state[x:x + 4][:offset]
            if not isInv:
                offset += 1
            elif isInv:
                offset -= 1
        if isInv: 
            return self.stateMatrix(''.join(state))
        return state

    def SubWord(self, byte):
    # Key Expansion routine que pega uma palavra de entrada de quatro bytes 
    # e aplica uma substituição S-box.
        return ((self.sBox[(byte >> 24 & 0xff)] << 24) + (self.sBox[(byte >> 16 & 0xff)] << 16) +
                (self.sBox[(byte >> 8 & 0xff)] << 8) + self.sBox[byte & 0xff])

    def SubBytes(self, state, isInv):
    # Transforma a matriz de estado usando um byte não linear S-box 
    # que opera em cada um dos bytes de estado independentemente.
        if not isInv: 
            return ['%02x' % self.sBox[int(state[x], 16)] for x in range(16)]
        elif isInv: 
            return ['%02x' % self.sBoxInverted[int(state[x], 16)] for x in range(16)]

    # noinspection PyAssignmentToLoopOrWithParameter
    def MixColumns(self, state, isInv):
    # Opera no estado coluna por coluna, tratando cada coluna como um polinômio de quatro termos. 
    # As colunas são consideradas polinômios sobre o Galois Field (2 ^ 8) 
    # e módulo multiplicado x ^ 4 + 1 com um polinômio fixo a (x).
        if isInv: 
            fixed = [14, 9, 13, 11]; state = self.stateMatrix(''.join(state))
        else: 
            fixed = [2, 1, 1, 3]
        columns = [state[x:x + 4] for x in range(0, 16, 4)]
        row = [0, 3, 2, 1]
        col = 0
        output = []
        for _ in range(4):
            for _ in range(4):
                # noinspection PyTypeChecker
                output.append('%02x' % (
                    self.galoisField(int(columns[row[0]][col], 16), fixed[0]) ^
                    self.galoisField(int(columns[row[1]][col], 16), fixed[1]) ^
                    self.galoisField(int(columns[row[2]][col], 16), fixed[2]) ^
                    self.galoisField(int(columns[row[3]][col], 16), fixed[3])))
                row = [row[-1]] + row[:-1]
            col += 1
        return output

    def Cipher(self, expandedKey, data):
    # No início da cifra, a entrada é copiada para a matriz de estado. 
    # Depois de uma adição inicial da Round Key, a Matriz de Estado é transformada implementando
    # uma função de rodada 10, 12 ou 14 vezes (dependendo do comprimento da chave), 
    # com a rodada final ligeiramente diferente das primeiras rodadas Nr -1. 
    # A matriz de estado final é então copiada como saída.
        state = self.AddRoundKey(self.stateMatrix(data), expandedKey[0])
        for r in range(self.Nr - 1):
            state = self.SubBytes(state, False)
            state = self.ShiftRows(state, False)
            state = self.stateMatrix(''.join(self.MixColumns(state, False)))
            state = self.AddRoundKey(state, expandedKey[r + 1])

        state = self.SubBytes(state, False)
        state = self.ShiftRows(state, False)
        state = self.AddRoundKey(state, expandedKey[self.Nr])
        # print(state)
        return self.revertMatrix(state)

    def InvCipher(self, expandedKey, data):
        state = self.AddRoundKey(re.findall('.' * 2, data), expandedKey[self.Nr])

        for r in range(self.Nr - 1):
            state = self.ShiftRows(state, True)
            state = self.SubBytes(state, True)
            state = self.AddRoundKey(state, expandedKey[-(r + 2)])
            state = self.MixColumns(state, True)

        state = self.ShiftRows(state, True)
        state = self.SubBytes(state, True)
        state = self.AddRoundKey(state, expandedKey[0])
        return ''.join(state)

    def ExpandKey(self, key):
    # Pega a chave da cifra e executa uma rotina de expansão de chave para gerar uma programação de chave, 
    # gerando assim um total de Nb (Nr + 1) palavras.
        w = ['%08x' % int(x, 16) for x in re.findall('.' * 8, key)]
        i = self.Nk
        while i < self.Nb * (self.Nr + 1):
            temp = w[i - 1]
            if i % self.Nk == 0:
                temp = '%08x' % (self.SubWord(self.permuta(temp)) ^ (self.rcon[i // self.Nk] << 24))
            elif self.Nk > 6 and i % self.Nk == 4:
                temp = '%08x' % self.SubWord(int(temp, 16))
            w.append('%08x' % (int(w[i - self.Nk], 16) ^ int(temp, 16)))
            i += 1
        return [self.stateMatrix(''.join(w[x:x + 4])) for x in range(0, len(w), self.Nk)]

    def key_handler(self, key, isInv):
    # Obtém o comprimento da chave e define Nb, Nk de acordo e pede o Nr ao usuário.
        print("\n---------- MENU -----------\n")
        print("1 - 1 Rodada\n")
        print("2 - 3 Rodadas\n")
        print("3 - 5 Rodadas\n")
        print("4 - 9 Rodadas\n")
        print("5 - 13 Rodadas\n")
        choice = input("Insira o número desejado de rodadas: \n")
        if(choice == '1'): self.Nr = 1
        elif(choice == '2'): self.Nr = 3
        elif(choice == '3'): self.Nr = 5
        elif(choice == '4'): self.Nr = 9
        elif(choice == '5'): self.Nr = 10
        else:
            raise AssertionError(str(choice) + " é uma escolha inválida! Use o menu exibido acima.")
        # chave de 128 bits
        if len(key) == 32:
            self.Nb = 4; self.Nk = 4
        # chave de 192 bits
        elif len(key) == 48:
            self.Nb = 4; self.Nk = 6
        # chave de 256 bits
        elif len(key) == 64:
            self.Nb = 4; self.Nk = 8
        # Gera erro com tamanho de chave inválido
        else: 
            raise AssertionError("%s é uma chave inválida'!\n Use uma chave de 128 bits, 192 bits ou 256 bits!" % key)
        # Retorna a chave expandida
        if not isInv: 
            return self.ExpandKey(key)
        # Retorna a chave expandida invertida
        if isInv: 
            return [re.findall('.' * 2, self.revertMatrix(x)) for x in self.ExpandKey(key)]

    def aes_main(self, data, key, isInv):
    # Lida com os modos de criptografia e descriptografia
        # Obtém o conjunto de chaves expandidas
        expanded_key = self.key_handler(key, isInv)
        # Criptografa usando o modo ECB
        if self.mode == 'ecb': return self.ecb(data, expanded_key, isInv)
        # Criptografa usando o modo CBC
        elif self.mode == 'ctr': return self.ctr(data, expanded_key, isInv)
        # Gera erro em modo inválido
        else: 
            raise AttributeError("\n\n\t Os modos de operação AES suportados são ['ecb', 'ctr']")

    def encryption(self, data, key):
    # Função principal da criptografia AES
        return self.aes_main(data, key, False)

    def decryption(self, data, key):
    # Função principal da descriptografia AES
        return self.aes_main(data, key, True)

    @staticmethod
    def xor(first, last):
        """ Xor method for CTR usage    
    
        :param first: first encrypted block
        :param last: last encrypted block
        :return: Xor output of two blocks """
        first = re.findall('.' * 2, first)
        last = re.findall('.' * 2, last)
        return ''.join('%02x' % (int(first[x], 16) ^ int(last[x], 16)) for x in range(16))

    def ctr(self, data, expanded_key, isInv):
        """ CTR mode:
        In CBC mode, each block of dataDecrypt is XORed with the
        previous ciphertext block before being encrypted.

        Denoted as:
            Encryption: Ci = Ek(Pi xor C(i-1)) and C0 = IV
            Decryption: Pi = Dk(Ci) xor C(i-1) and C0 = IV

        :param data: Data to be encrypted (type defined by input type)
        :param expanded_key: The AES expanded key set
        :param isInv:
        :return: Data as string or binary data (defined by output type)"""
        if self.iv == None: 
            raise AttributeError("No Iv found!")
        if self.input == 'hex':
            if type(data) != list: data = data.split()
            blocks = [self.iv]; last = [self.iv] + data
            if not isInv:
                [blocks.append(self.Cipher(expanded_key, self.xor(blocks[-1], x))) for x in data]
                return blocks[1:]
            elif isInv:
                return ''.join([self.xor(self.InvCipher(expanded_key, data[x]), last[x]) for x in range(len(data))])
        elif self.input == 'data':
            if not isInv:
                data = re.findall('.' * 32, binascii.hexlify(self.padding(data)).decode()); blocks = [self.iv]
                [blocks.append(self.Cipher(expanded_key, self.xor(blocks[-1], x))) for x in data]
                return b''.join(binascii.unhexlify(x.encode()) for x in blocks[1:])
            elif isInv:
                data = re.findall('.' * 32, binascii.hexlify(data).decode()); last = [self.iv] + data
                return self.unpadding(b''.join(binascii.unhexlify(x.encode()) for x in [self.xor(
                    self.InvCipher(expanded_key, data[x]), last[x]) for x in range(len(data))]))

        # Raise error on invalid input
        else: 
            raise AttributeError("\n\n\t As entradas AES suportadas são ['hex', 'data']")

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
            if not isInv: return self.Cipher(expanded_key, ''.join('%02x' % x for x in self.padding(data.encode())))
            elif isInv: return str(self.unpadding(binascii.unhexlify(self.InvCipher(expanded_key, data).encode())))[2:-1]
        # Criptografa um fluxo de dados binários
        elif self.input == 'data':
            if not isInv: 
                return b''.join(binascii.unhexlify(self.Cipher(
                expanded_key, str(binascii.hexlify(x))[2:-1]).encode()) for x in self.unblock(self.padding(data)))
            if isInv: 
                return b''.join(binascii.unhexlify(self.InvCipher(
                expanded_key, str(binascii.hexlify(x))[2:-1]).encode()) for x in self.unblock(self.padding(data)))
        # Gera erro com entrada inválida
        else: 
            raise AttributeError("\n\n\t Os tipos de entrada suportados são ['hex', 'text', 'data']")
