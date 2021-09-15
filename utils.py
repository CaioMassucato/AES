# -*- coding: utf-8 -*-

import binascii
import re
from constantes import sBox, sBoxInverted

def AddRoundKey(state, key):
    # Adiciona uma Round Key ao estado usando uma operação XOR.
        return ['%02x' % (int(state[x], 16) ^ int(key[x], 16)) for x in range(16)]

def SubWord(byte):
    # Key Expansion routine que pega uma palavra de entrada de quatro bytes 
    # e aplica uma substituição S-box.
    return ((sBox[(byte >> 24 & 0xff)] << 24) + (sBox[(byte >> 16 & 0xff)] << 16) +
            (sBox[(byte >> 8 & 0xff)] << 8) + sBox[byte & 0xff])

def SubBytes(state, isInv):
# Transforma a matriz de estado usando um byte não linear S-box 
# que opera em cada um dos bytes de estado independentemente.
    if not isInv: 
        return ['%02x' % sBox[int(state[x], 16)] for x in range(16)]
    elif isInv: 
        return ['%02x' % sBoxInverted[int(state[x], 16)] for x in range(16)]

def padding(data, block = 16):
# Método de preenchimento dos dados
# consiste em inserir dados em uma mensagem antes da cifração 
    if block < 2 or block > 255:
        raise ValueError("Tamanho do bloco deve ser < 2 e > 255")

    if len(data) == block: return data
    padded = block - (len(data) % block)
    return data + binascii.unhexlify(('%02x' % int(padded)).encode()) + b'\x00' * (padded - 1)

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

def unblock(data, size = 16):
# Desbloqueia dados binários
    # Retorna blocos de 64 bits de dados
    return [data[x:x + size] for x in range(0, len(data), size)]

def permuta(word):
# Seleciona uma palavra [a0, a1, a2, a3] como entrada e executa uma 
# permutação cíclica que retorna a palavra [a1, a2, a3, a0].
    return int(word[2:] + word[0:2], 16)

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

def revertMatrix(state):
    # Inverte o formato da Matriz de Estado como str
        columns = [state[x:x + 4] for x in range(0, 16, 4)]
        return ''.join(''.join([columns[0][x], columns[1][x], columns[2][x], columns[3][x]]) for x in range(4))

def ShiftRows(state, isInv):
    # Altera o estado, deslocando ciclicamente as últimas 
    # três linhas do estado por diferentes deslocamentos.
        offset = 0
        if isInv: 
            state = re.findall('.' * 2, revertMatrix(state))
        for x in range(0, 16, 4):
            state[x:x + 4] = state[x:x + 4][offset:] + state[x:x + 4][:offset]
            if not isInv:
                offset += 1
            elif isInv:
                offset -= 1
        if isInv: 
            return stateMatrix(''.join(state))
        return state

# noinspection PyAssignmentToLoopOrWithParameter
def MixColumns(state, isInv):
# Opera no estado coluna por coluna, tratando cada coluna como um polinômio de quatro termos. 
# As colunas são consideradas polinômios sobre o Galois Field (2 ^ 8) 
# e módulo multiplicado x ^ 4 + 1 com um polinômio fixo a (x).
    if isInv: 
        fixed = [14, 9, 13, 11]; state = stateMatrix(''.join(state))
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
                galoisField(int(columns[row[0]][col], 16), fixed[0]) ^
                galoisField(int(columns[row[1]][col], 16), fixed[1]) ^
                galoisField(int(columns[row[2]][col], 16), fixed[2]) ^
                galoisField(int(columns[row[3]][col], 16), fixed[3])))
            row = [row[-1]] + row[:-1]
        col += 1
    return output

def xor(first, last):
        """ Xor method for CTR usage    
    
        :param first: first encrypted block
        :param last: last encrypted block
        :return: Xor output of two blocks """
        first = re.findall('.' * 2, first)
        last = re.findall('.' * 2, last)
        return ''.join('%02x' % (int(first[x], 16) ^ int(last[x], 16)) for x in range(16))