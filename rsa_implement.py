import random
import struct
import time
from sieve_base import sieve_base
import math

random.seed(time.time())
randfunc = random.randbytes


class RSA:
    def __init__(self):
        pass

    def encrypt_plaintext(self, plaintext):
        if type(plaintext) is str:
            plaintext = plaintext.encode()
        m = self.bytes_to_long(plaintext)
        return self.long_to_bytes(self.encrypt(m))

    def decrypt_ciphertext(self, ciphertext):
        if type(ciphertext) is str:
            ciphertext = ciphertext.encode()
        c = self.bytes_to_long(ciphertext)
        return self.long_to_bytes(self.decrypt(c))

    def encrypt(self, m):
        return self.power(m, self.e, self.n)

    def decrypt(self, c):
        return self.power(c, self.d, self.n)

    def getPrime(self, N):
        """Return a random N-bit prime number.
        N must be an integer larger than 1.
        """
        if N < 2:
            raise ValueError("N must be larger than 1")
        while True:
            number = self.getRandomNBitInteger(N) | 1
            if self.isPrime(number):
                break
        return number

    def getRandomNBitInteger(self, N):
        """Return a random number with exactly N-bits,
        i.e. a random number between 2**(N-1) and (2**N)-1.
        """
        value = self.getRandomInteger(N - 1)
        value |= 2 ** (N - 1)                # Ensure high bit is set
        assert self.size(value) >= N
        return value

    def getRandomInteger(self, N):
        """Return a random number at most N bits long."""
        S = randfunc(N >> 3)
        odd_bits = N % 8
        if odd_bits != 0:
            rand_bits = ord(randfunc(1)) >> (8-odd_bits)
            S = struct.pack('B', rand_bits) + S
        value = self.bytes_to_long(S)
        return value

    def bytes_to_long(self, s):
        """Convert a byte string to a long integer (big endian).
        In Python 3.2+, use the native method instead::
            >>> int.from_bytes(s, 'big')
        For instance::
            >>> int.from_bytes(b'\x00P', 'big')
            80
        This is (essentially) the inverse of :func:`long_to_bytes`.
        """
        acc = 0
        unpack = struct.unpack
        length = len(s)
        if length % 4:
            extra = (4 - length % 4)
            s = b'\x00' * extra + s
            length = length + extra
        for i in range(0, length, 4):
            acc = (acc << 32) + unpack('>I', s[i:i + 4])[0]
        return acc

    def size(self, N):
        """Returns the size of the number N in bits."""
        if N < 0:
            raise ValueError(
                "Size in bits only available for non-negative numbers")
        return N.bit_length()

    def isPrime(self, N, false_positive_prob=1e-6):
        """Test if a number *N* is a prime.
        Args:
            false_positive_prob (float):
            The statistical probability for the result not to be actually a
            prime. It defaults to 10\ :sup:`-6`.
            Note that the real probability of a false-positive is far less.
            This is just the mathematically provable limit.
            randfunc (callable):
            A function that takes a parameter *N* and that returns
            a random byte string of such length.
        Return:
            `True` is the input is indeed prime.
        """
        if N < 3 or N & 1 == 0:
            return N == 2
        for p in sieve_base:
            if N == p:
                return True
            if N % p == 0:
                return False
        rounds = int(math.ceil(-math.log(false_positive_prob)/math.log(4)))
        return bool(self._rabinMillerTest(N, rounds))

    def _rabinMillerTest(self, n, rounds):
        """_rabinMillerTest(n:long, rounds:int, randfunc:callable):int
        Tests if n is prime.
        Returns 0 when n is definitely composite.
        Returns 1 when n is probably prime.
        Returns 2 when n is definitely prime.
        """
        # check special cases (n==2, n even, n < 2)
        if n < 3 or (n & 1) == 0:
            return n == 2
        # n might be very large so it might be beneficial to precalculate n-1
        n_1 = n - 1
        # determine m and b so that 2**b * m = n - 1 and b maximal
        b = 0
        m = n_1
        while (m & 1) == 0:
            b += 1
            m >>= 1
        tested = []
        # we need to do at most n-2 rounds.
        for i in range(min(rounds, n-2)):
            # randomly choose a < n and make sure it hasn't been tested yet
            a = self.getRandomRange(2, n)
            while a in tested:
                a = self.getRandomRange(2, n)
            tested.append(a)
            # do the rabin-miller test
            z = self.power(a, m, n)  # (a**m) % n
            if z == 1 or z == n_1:
                continue
            composite = 1
            for r in range(b):
                z = (z * z) % n
                if z == 1:
                    return 0
                elif z == n_1:
                    composite = 0
                    break
            if composite:
                return 0
        return 1

    def getRandomRange(self, a, b):
        """Return a random number *n* so that *a <= n < b*."""
        range_ = b - a - 1
        bits = self.size(range_)
        value = self.getRandomInteger(bits)
        while value > range_:
            value = self.getRandomInteger(bits)
        return a + value

    def long_to_bytes(self, n, blocksize=0):
        """Convert a positive integer to a byte string using big endian encoding.
        If :data:`blocksize` is absent or zero, the byte string will
        be of minimal length.
        Otherwise, the length of the byte string is guaranteed to be a multiple
        of :data:`blocksize`. If necessary, zeroes (``\\x00``) are added at the left.
        .. note::
            In Python 3, if you are sure that :data:`n` can fit into
            :data:`blocksize` bytes, you can simply use the native method instead::
                >>> n.to_bytes(blocksize, 'big')
            For instance::
                >>> n = 80
                >>> n.to_bytes(2, 'big')
                b'\\x00P'
            However, and unlike this ``long_to_bytes()`` function,
            an ``OverflowError`` exception is raised if :data:`n` does not fit.
        """
        if n < 0 or blocksize < 0:
            raise ValueError("Values must be non-negative")
        result = []
        pack = struct.pack
        # Fill the first block independently from the value of n
        bsr = blocksize
        while bsr >= 8:
            result.insert(0, pack('>Q', n & 0xFFFFFFFFFFFFFFFF))
            n = n >> 64
            bsr -= 8
        while bsr >= 4:
            result.insert(0, pack('>I', n & 0xFFFFFFFF))
            n = n >> 32
            bsr -= 4
        while bsr > 0:
            result.insert(0, pack('>B', n & 0xFF))
            n = n >> 8
            bsr -= 1
        if n == 0:
            if len(result) == 0:
                bresult = b'\x00'
            else:
                bresult = b''.join(result)
        else:
            # The encoded number exceeds the block size
            while n > 0:
                result.insert(0, pack('>Q', n & 0xFFFFFFFFFFFFFFFF))
                n = n >> 64
            result[0] = result[0].lstrip(b'\x00')
            bresult = b''.join(result)
            # bresult has minimum length here
            if blocksize > 0:
                target_len = ((len(bresult) - 1) // blocksize + 1) * blocksize
                bresult = b'\x00' * (target_len - len(bresult)) + bresult
        return bresult

    def inverse(self, u, v):
        """The inverse of :data:`u` *mod* :data:`v`."""
        if v == 0:
            raise ZeroDivisionError("Modulus cannot be zero")
        if v < 0:
            raise ValueError("Modulus cannot be negative")
        u3, v3 = u, v
        u1, v1 = 1, 0
        while v3 > 0:
            q = u3 // v3
            u1, v1 = v1, u1 - v1*q
            u3, v3 = v3, u3 - v3*q
        if u3 != 1:
            raise ValueError("No inverse value can be computed")
        while u1 < 0:
            u1 = u1 + v
        return u1

    def GCD(self, x, y):
        """Greatest Common Denominator of :data:`x` and :data:`y`.
        """
        x = abs(x)
        y = abs(y)
        while x > 0:
            x, y = y % x, x
        return y

    def gcd(self, a, b):
        # Stein's Algorithm
        # GCD(0, b) == b; GCD(a, 0) == a,
        # GCD(0, 0) == 0
        if (a == 0):
            return b
        if (b == 0):
            return a
        # Finding K, where K is the
        # greatest power of 2 that
        # divides both a and b.
        k = 0
        while (((a | b) & 1) == 0):
            a = a >> 1
            b = b >> 1
            k = k + 1
        # Dividing a by 2 until a becomes odd
        while ((a & 1) == 0):
            a = a >> 1
        # From here on, 'a' is always odd.
        while (b != 0):
            # If b is even, remove all
            # factor of 2 in b
            while ((b & 1) == 0):
                b = b >> 1
            # Now a and b are both odd. Swap if
            # necessary so a <= b, then set
            # b = b - a (which is even).
            if (a > b):
                # Swap u and v.
                temp = a
                a = b
                b = temp
            b = (b - a)
        # restore common factors of 2
        return (a << k)

    def power(self, a, p, mod):
        if a % mod == 0:
            return 0
        if p == 0:
            return 1
        if p == 1:
            return a % mod
        remain = 1
        while True:
            if p % 2 == 0:
                p = p >> 1
            else:
                p = (p-1) >> 1
                remain = (remain * a) % mod
            a = (a**2) % mod
            if p == 1:
                return (a * remain) % mod

    def generate_prime_with_gap(self, p, key_bits):
        lower_bound = 2 ** (key_bits // 2 - 5)
        p_bits = p.bit_length()
        q_bits = key_bits - p_bits
        compare = p_bits > q_bits  # True: p > q, False: p < q
        while True:
            res = self.getRandomInteger(q_bits)
            if compare:
                if p - res < lower_bound:
                    continue
            else:
                if res - p < lower_bound:
                    continue
            if self.isPrime(res):
                break
        return res

    def p_and_q_generate(self):
        self.p = self.getPrime(self.key_bits // 2)
        self.q = self.generate_prime_with_gap(self.p, self.key_bits)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)

    def n_and_phi_generate(self):
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)

    def e_generate(self):
        while True:
            e = self.getPrime(self.size(self.phi) // 2)
            if self.GCD(e, self.phi) == 1:
                self.e = e
                break

    def d_generate(self):
        assert self.GCD(
            self.e, self.phi) == 1, "e does not have an inverted number."
        self.d = self.inverse(self.e, self.phi)
