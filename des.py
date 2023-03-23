import functools

class DESBasic(object):
	''' Basic class for DES, I put some common function and variable here.
		Class KeyGenerator and SimpleDes are subclass of this one.
	'''

	# length of packet and bit
	pl = 64
	bl =  8

	# circle in encrypt, sometimes you can increase the value of circle to add security.
	# 16 is official standard.
	circle = 16

	def permutate(self, group, matrix):
		'''	Matrix permutate, matrix contains target position.
			The value of matrix begin with 1
		'''
		line, row = len(matrix), len(matrix[0])

		L = range(line*row)
		for l in range(line):
			for r in range(row):
				# '1' as revise
				pos = matrix[l][r] - 1
				L[l*row+r] = group[pos]

		return L

	def getBinMatrixFromHex(self, key):
		''' Reduce input, form hex string into binary list.'''
		key = self.hex2bin(key)
		key = self.padding(key, self.pl)[:self.pl]
		key = map(int, key)
		return key

	def padding(self, plain, length = 64, char = '0'):
		''' String padding, left justifying.'''
		plainLen = len(plain)
		quotient = plainLen // length

		if plainLen % length != 0:
			patch = bin(length - len(plain) % length)[2:]
			return plain.ljust(length * (quotient + 1) - len(patch), char) + patch
		else:
			return plain

	def hex2bin(self, hexs):
		''' From hex string to bin string.
			Right justifying, '0' padding.
		'''
		return (bin(int(hexs, 16)))[2:].rjust(len(hexs) * 4, '0')

	def printHexList(self, l, length = 8):
		''' Print binary list in Hex format.
			'Length' controls how much charactor one line.
		'''
		for i in range(len(l) / length):
			print (hex(int("".join(map(str,l[i*length:(i+1)*length])), 2))[2:].rjust(2, '0').upper(),
		print)

class KeyGenerator(DESBasic):
	''' Key gengerator, input hex key string, generate key list
		Visit like this, KG[0-63]
	'''

	# permutation selection matrix
	__PS1 = (
		(57, 49, 41, 33, 25, 17,  9),
		( 1, 58, 50, 42, 34, 26, 18),
		(10,  2, 59, 51, 43, 35, 27),
		(19, 11,  3, 60, 52, 44, 36),
		(63, 55, 47, 39, 31, 23, 15),
		( 7, 62, 54, 46, 38, 30, 22),
		(14,  6, 61, 53, 45, 37, 29),
		(21, 13, 5 , 28, 20, 12,  4),
	)
	__PS2 = (
		(14, 17, 11, 24,  1,  5),
		( 3, 28, 15,  6, 21, 10),
		(23, 19, 12,  4, 26,  8),
		(16,  7, 27, 20, 13,  2),
		(41, 52, 31, 37, 47, 55),
		(30, 40, 51, 45, 33, 48),
		(44, 49, 39, 56, 34, 53),
		(46, 42, 50, 36, 29, 32),
	)

	# Left circle bit.
	__LC = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

	def __init__(self, key):
		self.permutateSelection1 = functools.partial(self.permutate, matrix = self.__PS1)
		self.permutateSelection2 = functools.partial(self.permutate, matrix = self.__PS2)

		self.__key = self.getBinMatrixFromHex(key)
		self.verity()

		self.keys = []
		self.generate()

	def __getitem__(self, n):
		if isinstance(n, int):
			if 0 <= n <= len(self.keys):
				return self.keys[n]
		else:
			raise ValueError("Argument need int, [%s] given." % type(n))

	# Generate keys, saved into self.keys
	def generate(self):
		key = self.permutateSelection1(self.__key)

		ci = key[:len(key)/2]
		di = key[len(key)/2:]

		for i in range(0, self.circle):
			lc = self.__LC[i]
			ci = self.leftCircle(ci, lc)
			di = self.leftCircle(di, lc)

			ki = self.permutateSelection2(ci+di)
			self.keys.append(ki)

	def verity(self):
		return True

	def leftCircle(self, l, bit):
		''' Left circle b bit for list, add head into tail.'''
		return l[bit:] + l[:bit]

class SimpleDes(DESBasic):
	'''	Main class for AES encrypt.'''

	# round function packet length
	rl = 6

	# Initial permutate key matrix
	# And inverse initial permutate key matrix
	__IP = (
		(58, 50, 42, 34, 26, 18, 10, 2),
		(60, 52, 44, 36, 28, 20, 12, 4),
		(62, 54, 46, 38, 30, 22, 14, 6),
		(64, 56, 48, 40, 32, 24, 16, 8),
		(57, 49, 41, 33, 25, 17,  9, 1),
		(59, 51, 43, 35, 27, 19, 11, 3),
		(61, 53, 45, 37, 29, 21, 13, 5),
		(63, 55, 47, 39, 31, 23, 15, 7),
	)
	__IIP = (
		(40, 8, 48, 16, 56, 24, 64, 32),
		(39, 7, 47, 15, 55, 23, 63, 31),
		(38, 6, 46, 14, 54, 22, 62, 30),
		(37, 5, 45, 13, 53, 21, 61, 29),
		(36, 4, 44, 12, 52, 20, 60, 28),
		(35, 3, 43, 11, 51, 19, 59, 27),
		(34, 2, 42, 10, 50, 18, 58, 26),
		(33, 1, 41,  9, 49, 17, 57, 25),
	)

	# Expend transformation matrix.
	__ET = (
		(32,  1,  2,  3,  4,  5),
		( 4,  5,  6,  7,  8,  9),
		( 8,  9, 10, 11, 12, 13),
		(12, 13, 14, 15, 16, 17),
		(16, 17, 18, 19, 20, 21),
		(20, 21, 22, 23, 24, 25),
		(24, 25, 26, 27, 28, 29),
		(28, 29, 30, 31, 32,  1),
	)

	# P permutate matrix.
	__PP = (
		(16,  7, 20, 21),
		(29, 12, 28, 17),
		( 1, 15, 23, 26),
		( 5, 18, 31, 10),
		( 2,  8, 24, 14),
		(32, 27,  3,  9),
		(19, 13, 30,  6),
		(22, 11,  4, 25),
	)

	# S Sandbox matrix
	__SB = (
		(
			(14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7),
			(0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8),
			(4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0),
			(15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13)
		),
		(
			(15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10),
			(3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5),
			(0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15),
			(13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9)
		),
		(
			(10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8),
			(13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1),
			(13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7),
			(1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12)
		),
		(
			(7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15),
			(13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9),
			(10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4),
			(3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14)
		),
		(
			(2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9),
			(14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6),
			(4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14),
			(11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3)
		),
		(
			(12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11),
			(10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 12, 14, 0, 11, 3, 8),
			(9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6),
			(4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13)
		),
		(
			(4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1),
			(13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6),
			(1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2),
			(6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12)
		),
		(
			(13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7),
			(1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2),
			(7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8),
			(2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11)
		)
	)

	def __init__(self, key = "AABB09182736CCDD"):
		''' Generate keys.'''

		self.initialPermutate = functools.partial(self.permutate, matrix = self.__IP)
		self.inverseInitialPermutate = functools.partial(self.permutate, matrix =self.__IIP)
		self.extendTrans = functools.partial(self.permutate, matrix = self.__ET)
		self.replaceOperate = functools.partial(self.permutate, matrix = self.__PP)

		self.keys = KeyGenerator(key)

	def encrypt(self, plain = "123456ABCD132536"):
		''' Data encrypt.'''
		self.plain = self.getBinMatrixFromHex(plain)
		self.plains = self.devide(self.plain, self.pl)

		self.ciphers = []
		for plain in self.plains:
			cipher = self.groupEncrypt(plain)
			self.ciphers += cipher

		return self.ciphers

	def devide(self, plain, length):
		''' Devide plain or cipher into groups.'''

		L = []
		for i in range(0, len(plain), length):
			L.append(plain[i:i+length])

		return L

	def groupEncrypt(self, plain):
		''' Encrypt in each group.'''
		circle = self.circle

		plain = self.initialPermutate(plain)

		L, R = range(circle+1), range(circle+1)

		L[0] = plain[:len(plain)/2]
		R[0] = plain[len(plain)/2:]

		for i in range(1, circle):
			L[i] = R[i-1]
			R[i] = self.round(R[i-1], self.keys[i-1])
			R[i] = self.listXor(L[i-1], R[i])

		L[circle] = self.round(R[circle - 1], self.keys[circle - 1])
		L[circle] = self.listXor(L[circle - 1], L[circle])
		R[circle] = R[circle - 1]

		result = self.inverseInitialPermutate(L[circle]+R[circle])

		return result

	def listXor(self, l, r):
		''' Data XOR, map in every bit.'''
		L = []
		for i in range(len(l)):
			L.append(l[i]^r[i])

		return L

	def round(self, text, key):
		''' Round function, core of encryption'''
		text = self.extendTrans(text)
		result = self.listXor(text, key)
		result = self.selectCompressTrans(result)
		result = self.replaceOperate(result)
		return result

	def selectCompressTrans(self, text):
		texts = self.devide(text, self.rl)

		rtn = []
		for i in range(len(texts)):
			rtn += self.subSelectTrans(texts[i], self.__SB[i])

		return rtn

	def subSelectTrans(self, text, key):
		line = text.pop(0)*2 + text.pop()
		raw = int("".join(map(str, text)), 2)

		value = key[line][raw]

		return map(int, bin(value)[2:].rjust(len(key), '0'))

if __name__ == "__main__":
	des = SimpleDes()
	des.printHexList(des.encrypt())

