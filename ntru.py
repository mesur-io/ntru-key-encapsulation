#
# This is an example NTRU implementation, along with a simple example of the
# key exchange at the end.
# This is *only* example code, and should be used only to gain an
# understanding of how NTRU works; it should *not* be used by any real
# application:
# - It uses Python's internal rng; that's not crypto secure
# - NTRU needs to be done in constant time (or, at least, time independent of
#   any secret data.  This doesn't try to do that
# And, of course, there's the practical issue that this implementation is
# bog slow

import random     # To get random bits
import hashlib    # To get SHA-3

def mod3(x):
    # This converts:
    #  Numbers 0 mod 3 (..., -6, -3, 0, 3, 6, ...) -> 0
    #  Numbers 1 mod 3 (..., -5, -2, 1, 4, 7, ...) -> 1
    #  Numbers 2 mod 3 (..., -4, -1, 2, 5, 8, ...) -> -1
    # This relies on python getting negative modulii correct; -1 % 3 = 2
    # Other languages may need more complicated approaches
    return ((x+1) % 3) - 1

def hash_two_strings(S, C):
    # This SHA3-256 hashes the concatination of two strings
    hash = hashlib.sha3_256()
    hash.update( S )
    hash.update( C )
    return hash.digest()
       
class NTRU_base:
    #
    # This is the low level code that deals with NTRU operations
    # It is initialized with the NTRU parameter set we will be using
    # This parameter set is summarized by the variables:
    #  - n, the size of the polynomial
    #  - q, the modulus of the elements in the polynomail

    # Initialize ourselves to do the specified parameter set
    def __init__(self, parameter_set):
        if parameter_set == 'hps2048677':
            self.n = 677
            self.q = 2048
        elif parameter_set == 'hps4096821':
            self.n = 821
            self.q = 4096
        elif parameter_set == 'tiny':    # For testing purposes only
            self.n = 17
            self.q = 512
        else:
            raise ValueError    # Undefined parameter set
 
    def modq(self, x):
        # This converts x into x mod q, where x mod q is in balanced
        # representation, that is, within the interval [-q/2, ..., q/2)
        return ((x+self.q//2) % self.q) - self.q//2

    def add(self, A, B):
        # Add two polynomials (mod q)
        Sum = []
        for x in range(self.n):
            Sum.append( self.modq(A[x] + B[x]) )
        return Sum

    def subtract(self, A, B):
        # Subtract two polynomials (mod q)
        Sum = []
        for x in range(self.n):
            Sum.append( self.modq(A[x] - B[x]) )
        return Sum

    def multiply(self, A, B):
        # Multiply two polynomials (mod q)
        Product = []
        for _ in range(self.n):
            Product.append(0)
        for x in range(self.n):
            for y in range(self.n):
                z = (x + y) % self.n
                Product[z] = Product[z] + A[x]*B[y]
        for x in range(self.n):
            Product[x] = self.modq( Product[x] )
        return Product

    def multiply_3(self, A, B):
        # Multiply two polynomials (mod q)
        Product = []
        for _ in range(self.n):
            Product.append(0)
        for x in range(self.n):
            for y in range(self.n):
                z = (x + y) % self.n
                Product[z] = Product[z] + A[x]*B[y]
        for x in range(self.n):
            Product[x] = mod3( Product[x] )
        return Product

    def mod_phin(self, A):
        # Reduce the polynomial A mod x^(n-1) + x^(n-2) + ... + 1
        B = A
        msdigit = B[ self.n-1 ]
        for x in reversed(range(self.n-1)):
            B[x] = self.modq(B[x] - msdigit)
        B[ self.n-1 ] = 0
        return B

    def multiply_int(self, A, val):
        # Multiply the polynomial A by the integer al
        Product = []
        for x in range(self.n):
            v = self.modq(A[x] * val)
            Product.append(v)
        return Product

    def invert(self, A):
        # Invert the polynomial A (mod q)

        # First, invert the polynomial A (mod 2)
        V = []
        for _ in range(self.n):
            V.append(0)
        W = [1]
        for _ in range(self.n-1):
            W.append(0)
        F = []
        for _ in range(self.n):
            F.append(1)
        G = []
        for x in range(self.n-1):
            G.append( (A[self.n-2-x] ^ A[self.n-1]) % 2 )
        G.append(0)
        delta = 1
        for _ in range(2*self.n-3):
            for x in reversed(range(self.n-1)):
                V[x] = V[x-1]
            V[self.n-1] = 0
            if delta > 0 and G[0] != 0:
                swap = -1
                delta = -delta
            else:
                swap = 0
            delta = delta + 1
            if swap:
                T = F; F = G; G = T
                T = V; V = W; W = T
            if F[0] != 0 and G[0] != 0:
                for x in range(self.n):
                    G[x] = G[x]^F[x]
                    W[x] = W[x]^V[x]
            for x in range(self.n-1):
                G[x] = G[x+1]
            G[self.n-1] = 0
        R = []
        for x in range(self.n-1):
            R.append( V[self.n-2-x] )
        R.append(0)
        B = []
        for x in range(self.n):
            B.append( self.modq( -A[x] ) )

        # Now that we've computed the inverse mod 2, do four iterations
        # of Newton-Raphson to extend it to cover all the bits of q, which
        # is a power of 2
        # 4 iterations are sufficient for q < 65535
        for _ in range(4):
            C = self.multiply( R, B )
            C[0] = self.modq(C[0] + 2)
            R = self.multiply( R, C )
        return R

    def invert_3(self, A):
        # Invert the polynomial A (mod 3)
        V = []
        for _ in range(self.n):
            V.append(0)
        W = [1]
        for _ in range(self.n-1):
            W.append(0)
        F = []
        for _ in range(self.n):
            F.append(1)
        G = []
        for x in range(self.n-1):
            G.append( mod3(A[self.n-2-x] - A[self.n-1]) )
        G.append(0)
        delta = 1
        for _ in range(2*self.n-3):
            for x in reversed(range(self.n-1)):
                V[x] = V[x-1]
            V[0] = 0
            sign = mod3( -F[0] * G[0] )
            if delta > 0 and G[0] != 0:
                swap = 1
                delta = -delta
            else:
                swap = 0
            delta = delta + 1
            if swap:
                T = F; F = G; G = T
                T = V; V = W; W = T
            for x in range(self.n):
                G[x] = mod3( G[x] + sign*F[x] )
                W[x] = mod3( W[x] + sign*V[x] )
            for x in range(self.n-1):
                G[x] = G[x+1]
            G[self.n-1] = 0

        sign = F[0]
        R = []
        for x in range(self.n-1):
            R.append( mod3( sign*V[self.n-2-x] ) )
        R.append(0)
        return R

    def sample_iid(self):
        # Generate a random trinary polynomial (that is, with all the terms
        # either 0, 1 or -1); with the highest term being 0
        F = []
        for _ in range(self.n-1):
            v = mod3(random.getrandbits(8))
            F.append(v)
        F.append(0)
        return F

    def sample_fixed_type(self):
        # Generate a random trinary polynomial of the proper weight; that is,
        # n/16 of the digits are 1, n/16 are -1 and the rest are 0
        S = []
        for x in range(self.n - 1):
            v = 4*random.getrandbits(30)
            if x < self.n//16:
                v = v + 1
            elif x < self.n//8:
                v = v + 2
            S.append(v)
        S.sort()     # This should be a constant time sort
        for x in range(self.n - 1):
            S[x] = mod3(S[x] % 4)
        S.append(0)
        return S

class NTRU_publickey(NTRU_base):
    #
    # This is the code that deals with NTRU public operations, specifically
    # encapsulate
    #
    # This object doesn't hold a public key (there's no reason to); so it
    # has no variables (other than the parameter set inherited from NTRU_base)

    # This encodes a polynomial into a byte string using the pack_Rq0 procedure
    # This assumes that the polynomial is a multiple of x+1
    def pack_Rq0(self, H):
        list = bytearray()
        bit_out = 1
        next_val = 0
        for x in range(self.n-1):
            bit_in = 1
            while bit_in < self.q:
                next_bit = (H[x] // bit_in) % 2
                next_val = next_val + next_bit * bit_out
                bit_in = 2*bit_in
                bit_out = 2*bit_out
                if bit_out == 256:
                    list.append(next_val)
                    bit_out = 1
                    next_val = 0
        if bit_out > 1:
            list.append(next_val)
        return list

    # This converts a byte string (created by pack_Rq0) back into our
    # internal polynomial representation
    def unpack_Rq0(self, list):
        H = []
        bit_in = 1
        bit_out = 1
        next_val = 0
        total_bytes = 0
        x = 0
        inverse_sum = 0
        while total_bytes < self.n-1:
            next_bit = (list[x] // bit_in) % 2
            next_val = next_val + next_bit * bit_out
            bit_in = 2*bit_in
            if bit_in == 256:
                x = x + 1
                bit_in = 1
            bit_out = 2*bit_out
            if bit_out == self.q:
                H.append(self.modq(next_val))
                inverse_sum = inverse_sum - next_val
                bit_out = 1
                next_val = 0
                total_bytes = total_bytes+1
        H.append(self.modq(inverse_sum))
        return H

    # Pack a trinary polynomial (one whose elements are all 0, 1, -1)
    # into a bytestring.  This is used for hashing, and so it doesn't
    # matter that not all the elements of A make it into the string
    def pack_S3(self, A):
        list = bytearray()
        for x in range((self.n-1)//5):
            sum = 0
            mult = 1
                # Encode 5 consecutive elements into a single byte
            for y in range(5):
                val = A[5*x + y]
                if (val < 0):   # We encode -1 elements as '2'
                    val = 2
                sum = sum + mult*val
                mult = 3*mult

            list.append(sum % 256)
        return list

    #
    # This SHA3-256 hashes two trinary polynomials together
    def hash_two_trinary_polynomials(self, A, B):
        return hash_two_strings( self.pack_S3( A ), self.pack_S3( B ) )

    #
    # This is the deterministic public key encryption routine
    # It should not be called directly by the application
    def encrypt(self, public_key, R, M):
        # Unpack the public key
        H = self.unpack_Rq0(public_key)
        # If we were doing HRSS, we would lift M here

        # And we encrypt it by multiplying R*H, and then adding M
        RH = self.multiply( R, H )
        C = self.add( self.multiply( R, H ), M )

        # And that's the ciphertext (converted into the 'on-the-wire'
        # representation)
        return self.pack_Rq0(C)
    #
    # This is the KEM encapsulate routine
    # It returns the key share and the shared secret
    def kem_encapsulate(self, public_key):
        # Select random R, M polynomials
        R = self.sample_iid()
        M = self.sample_fixed_type()

        # Generate a ciphertext conveying those values
        C = self.encrypt(public_key, R, M)

        # Create a shared secret based on the random values we selected
        K = self.hash_two_trinary_polynomials(R, M)

        # And return the ciphertext, along with the shared secret
        return C, K

class NTRU_privatekey(NTRU_publickey):
    #
    # This is the code that deals with NTRU private operations, specifically
    # key_gen and encapsulate
    #
    # This can hold a private key; this private key is summarized by:
    #  - F, a secret trinary polynomial
    #  - H, the public key F^-1 G (where G is a secret balanced trinary
    #       polynomial)
    #  - H_inv, which is H^-1; not secret, but is useful during decryption
    #  - F_inv, which is F^-1 (computed over modulo 3)
    #  - S, which is a random 32 byte string

    #
    # This is the key generation routine; it returns the public key
    def key_gen(self):
        # Select small F, G parameters
        self.F = self.sample_iid()
        G = self.sample_fixed_type()

        # Multiply G by 3 (because, during decryption, we'll take
        # things modulo 3 to drop these G factors)
        G = self.multiply_int(G, 3)

        # And construct the public key
        FG = self.multiply(self.F, G)
        FG_inv = self.invert(FG)

        # H = F^-1 * G
        # This is the public key
        self.H = self.multiply(self.multiply(FG_inv, G), G)

        # H_inv = F * G^-1
        # This is computable from the public key; we use it to
        # speed up the decryption process
        self.H_inv = self.multiply(self.multiply(FG_inv, self.F), self.F)

        # F_inv = F^-1 (but this time, over polynomials modulo 3)
        self.F_inv = self.invert_3(self.F)

        # And select the random S parameter (used to disguise KEM failure)
        self.S = bytearray()
        for _ in range(32):
            self.S.append( random.randrange(256) )

        # And return the public key
        return self.pack_Rq0(self.H)

    #
    # Check if M is a legal value
    # This changes for HRSS
    # This should be done in constant time
    def check_m(self, M):
        if (M[self.n-1] != 0):
            return 0
        count_1 = 0
        count_2 = 0
        for x in range(self.n-1):
            v = M[x]
            if v == 1:
                count_1 = count_1 + 1
            elif v == -1:
                count_2 = count_2 + 1
            elif v != 0:
                return 0
        if count_1 == self.n//16 and count_2 == self.n//16:
            return 1
        return 0
    
    #
    # Check if R is a legal value
    # In this case, 'legal' means 'all values either 0, 1 or -1'
    # In a real implementation, this needs to be done in constant time
    def check_r(self, R):
        t = 0
        for x in range(self.n-1):
            v = R[x]
            # t will remain 0 if the value is in the range (-1, 0, 1, 2)
            t = t | ((v+1) & 0xfffc)
            # t will remain 0 if the value is in the range (-2, -1, 0, 1)
            t = t | ((v+2) & 0xfffc)

        # The last coefficient must also be 0
        t = t | R[self.n-1]

        if t == 0:
            return 1
        else:
            return 0

    #
    # This is the deterministic public key decryption routine
    # It should not be called directly by the application
    def decrypt(self, C):
        # Step one is suppose to check if C = 0 mod x+1; however because
        # of how the unpack_Rq0 logic works, that is always true
        A = self.multiply(C, self.F)
        M = self.multiply_3(A, self.F_inv)

        # If we do HRSS, this changes
        CMP = self.subtract( C, M )
        R = self.multiply( CMP, self.H_inv )
        R = self.mod_phin(R)

        # Check if R, M is a legal value
        success_flag = self.check_m(M)
        success_flag = success_flag & self.check_r(R)

        # If we failed (success_flag == 0), clear out M and R
        for x in range(self.n):
            M[x] = success_flag * M[x]
            R[x] = success_flag * R[x]

        return (R,M,success_flag)
 
    #
    # This is the KEM decapsulate routine; it is passed the key share and
    # returns a shared secret (either the valid one, or an error one)
    def kem_decapsulate(self, C_packed):
        C = self.unpack_Rq0(C_packed)
        (R, M, success_flag) = self.decrypt(C)
        K1 = self.hash_two_trinary_polynomials(R, M)
        K2 = hash_two_strings(self.S, C_packed)
        if success_flag == 1:
            return K1
        else:
            return K2

#
# Here is a quick example; a key exchange between Alice and Bob
# The convention this uses is: everything Alice owns is prefixed by 'a_'
# Everything Bob owns is prefixed by 'b_'
parameter_set = 'hps2048677'
# parameter_set = 'hps4096821'

# Step 1: Alice creates her private/public key:
a_privkey = NTRU_privatekey( parameter_set )
a_pubkey = a_privkey.key_gen()

# Step 2: Alice sends her public key as a keyshare
b_keyshare = a_pubkey
# print( 'Alice sends her public key:' );
# print( b_keyshare.hex() )

# Step 3: Bob creates a shared secret/ciphertext based on
# the keyshare he got from Alice
b_pubkey = NTRU_publickey( parameter_set )
(b_ciphertext, b_sharedsecret) = b_pubkey.kem_encapsulate(b_keyshare)

# Step 4: Bob sends his ciphertext as a keyshare
a_keyshare = b_ciphertext
# print( 'Bob sends his ciphertext:' );
# print( a_keyshare.hex() )

# Step 5: Alice generates her shared secret from the keyshare she got
# from Bob
a_sharedsecret = a_privkey.kem_decapsulate(a_keyshare)

# And at the end, we compare the two shared secrets
print( 'Alice computes this shared secret:' );
print( a_sharedsecret.hex() )
print( 'Bob computes this shared secret:' );
print( b_sharedsecret.hex() )
if a_sharedsecret == b_sharedsecret:
    print( 'It worked!' )   # Actually, we shouldn't be that surprised...
