#
# This is an example NTRU implementation, along with a simple example of the
# key exchange at the end.
# This is *only* example code, and should be used only to gain an
# understanding of how NTRU works; it should *not* be used by any real
# application:
# - It uses Python's internal rng; that's not crypto secure
# - NTRU needs to be done in constant time (or, at least, time independent of
#   any secret data.  While we make some attempts to do that (and added
#   comments where constant-time code is less clear), Python itself doesn't
#   claim to be constant time
# And, of course, there's the practical issue that this implementation is
# bog slow
#
# We tried to comment this code fairly well, after all, the whole point is
# to show how NTRU works internally.  If it feels like I've overexplained
# things, well, it's better than underexplaining things
#
# Internally, it uses a balanced representation to store polynomial
# coefficients; when the NTRU spec talks about values between 0 and Q-1, we
# actually store values between -Q/2 and Q/2-1.  Similarly, instead of storing
# values between 0 and 2, we store values between -1 and 1.  This simplifies
# some of the logic

import random     # To get random bits
import hashlib    # To get SHA-3

def mod3(x):
    # This converts:
    #  Numbers 0 mod 3 (..., -6, -3, 0, 3, 6, ...) -> 0
    #  Numbers 1 mod 3 (..., -5, -2, 1, 4, 7, ...) -> 1
    #  Numbers 2 mod 3 (..., -4, -1, 2, 5, 8, ...) -> -1
    # This relies on python getting negative modulii correct; -1 % 3 = 2
    # Other languages may need more complicated approaches
    # This also assumes that the % operator is constant time; this is unlikely
    # to be true
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

    def __init__(self, parameter_set):
        # Initialize ourselves to do the specified parameter set
        if parameter_set == 'hps2048509':
            self.n = 509
            self.q = 2048
        elif parameter_set == 'hps2048677':
            self.n = 677
            self.q = 2048
        elif parameter_set == 'hps4096821':
            self.n = 821
            self.q = 4096
        elif parameter_set == 'tiny':    # For testing purposes only
            self.n = 17
            self.q = 128
        else:
            raise ValueError    # Undefined parameter set
 
    def modq(self, x):
        # This converts x into x mod q, where x mod q is in balanced
        # representation, that is, within the interval [-q/2, ..., q/2)
        # Actually, if your implementation computes integers mod 2**16 or 2**32
        # internally, you could get away without this; just ignore the bits
        # above 11 (q=2048) or 12 (q=4096), and mask them at the end.
        # However, because python will use bignum's, we have to keep things
        # small ourselves.
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
        # Multiply two polynomials (mod 3)
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
        # Take the polynomial A (which is on degree n) and reduce it
        # mod x^n + x^(n-1) + ... + 1
        # That is, we return the n-1 degree polynomial
        # A - k(x^n + x^(n-1) + ... + 1) for the value k that makes this
        # of that degree
        B = A
        msdigit = B[ self.n-1 ]    # msdigit == k
        for x in range(self.n-1):
            B[x] = self.modq(B[x] - msdigit)
        B[ self.n-1 ] = 0
        return B

    def multiply_int(self, A, val):
        # Multiply the polynomial A by the integer val
        Product = []
        for x in range(self.n):
            v = self.modq(A[x] * val)
            Product.append(v)
        return Product

    def invert(self, A):
        # Invert the polynomial A (mod q), that is, return the polynomial
        # B such that A*B = 1 mod q, (x^n-1)/(x-1)
        # Note that we do it mod (x^n-1)/(x-1) rather than the more expected
        # x^n-1 (which is what we use in most places) because A will be a
        # multiple of x-1, and hence an inverse mod x^n-1 won't exist

        # The inversion code is not constant time.  To get around that, we
        # blind A by multiplying it by a random polynomial R, getting A*R.
        # A*R is uncorrelated to A; hence we don't mind if we leak it (because
        # it's effectively a random value).  We compute (A*R)^-1 in nonconstant
        # time; again, leakage here doesn't matter.  Once we have that, we
        # compute R*(A*R)^-1 = A^-1, giving us the answer we want
        R = []                   # Set R randomly
        for x in range(self.n):
            R.append( random.randrange(self.q) - self.q//2 )
        AR = self.multiply( A, R )

        # And now invert AR

        # First, we invert the polynomial AR (mod 2)
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
            G.append( (AR[self.n-2-x] ^ AR[self.n-1]) % 2 )
        G.append(0)
        delta = 1
        for _ in range(2*self.n-3):
            for x in reversed(range(self.n-1)):
                V[x] = V[x-1]
            V[self.n-1] = 0
            if delta > 0 and G[0] != 0:
                swap = True
                delta = -delta
            else:
                swap = False
            delta = delta + 1
            if swap:
                F, G = G, F
                V, W = W, V
            if F[0] != 0 and G[0] != 0:
                for x in range(self.n):
                    G[x] = G[x]^F[x]
                    W[x] = W[x]^V[x]
            for x in range(self.n-1):
                G[x] = G[x+1]
            G[self.n-1] = 0
        B = []
        for x in range(self.n-1):
            B.append( V[self.n-2-x] )
        B.append(0)
        # The lsbits of B are the lsbits of (A*R)^-1

        # Now that we've computed the inverse mod 2, do four iterations
        # of Newton-Raphson to extend it to cover all the bits of q, which
        # is a power of 2
        # 4 iterations are sufficient for q < 65536
        # Yes, Newton-Raphson works, even though the normal calculus-based way
        # of showing its correctness doesn't apply here; at the start of
        # iteration n, if the lower k bits of the inverse are correct, then
        # after iteration n, the lower 2k bits of the inverse are correct
        MAR = self.multiply_int( AR, -1 )
        for _ in range(4):
            C = self.multiply( B, MAR )
            C[0] = self.modq(C[0] + 2)
            B = self.multiply( B, C )
        # B is now (A*R)^-1

        # And return the final result, which is R*(A*R)^-1
        return self.multiply(B, R)

    def invert_3(self, A):
        # Invert the polynomial A (mod 3), that is, return the polynomial
        # B such that A*B = 1 mod 3, (x^n-1)/(x-1)

        # The inversion code is not constant time.  To get around that, we
        # blind A by multiplying it by a random polynomial R, getting A*R.
        # A*R is uncorrelated to A; hence we don't mind if we leak it (because
        # it's effectively a random value).  We compute (A*R)^-1 in nonconstant
        # time; again, leakage here doesn't matter.  Once we have that, we
        # compute R*(A*R)^-1 = A^-1, giving us the answer we want
        R = self.sample_iid()    # Set R randomly
        AR = self.multiply_3( A, R )

        # And now invert AR
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
            G.append( mod3(AR[self.n-2-x] - AR[self.n-1]) )
        G.append(0)
        delta = 1
        for _ in range(2*self.n-3):
            for x in reversed(range(self.n-1)):
                V[x] = V[x-1]
            V[0] = 0
            sign = mod3( -F[0] * G[0] )
            if delta > 0 and G[0] != 0:
                swap = True
                delta = -delta
            else:
                swap = False
            delta = delta + 1
            if swap:
                F, G = G, F
                V, W = W, V
            for x in range(self.n):
                G[x] = mod3( G[x] + sign*F[x] )
                W[x] = mod3( W[x] + sign*V[x] )
            for x in range(self.n-1):
                G[x] = G[x+1]
            G[self.n-1] = 0

        sign = F[0]
        B = []
        for x in range(self.n-1):
            B.append( mod3( sign*V[self.n-2-x] ) )
        B.append(0)
        # B is now (A*R)^-1

        # And return the final result, which is R*(A*R)^-1
        return self.multiply_3(B, R)

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
        # q/16-1 of the digits are 1, q/16-1 are -1 and the rest are 0
        # Because the number of 1 and -1 digits are the same, this polynomial
        # will always be a multiple of x-1
        S = []
        for x in range(self.n - 1):
            v = 4*random.getrandbits(30)  # Make the upper 30 bits random
            if x < self.q//16 - 1:        # For q/16-1 of the values,
                v = v + 1                 # set the two lsbits to 1
            elif x < self.q//8 - 2:       # For q/16-1 of the values,
                v = v + 2                 # set the two lsbits to 2
            S.append(v)
        S.sort()     # The sort order is (mostly) determined by the upper
                     # 30 bits, randomizing the order
                     # This should be a constant time sort, python's 
                     # built-in sort is not
        for x in range(self.n - 1):       # Strip off the upper 30 bits
            S[x] = mod3(S[x] % 4)         # and map 2 to -1
        S.append(0)                       # Add a 0 as the very last element
        return S

class NTRU_publickey(NTRU_base):
    #
    # This is the code that deals with NTRU public operations, specifically
    # encapsulate
    #
    # This object doesn't hold a public key (there's no reason to); so it
    # has no variables (other than the parameter set inherited from NTRU_base)

    # This encodes a polynomial into a byte string using the pack_Rq0 procedure
    # This assumes that the polynomial is a multiple of x-1 (which is always
    # true; H will always be a multiple of G, and we select G so that it is a
    # multiple of x-1)
    def pack_Rq0(self, H):
        list = bytearray()
        bit_out = 1
        next_val = 0
        for x in range(self.n-1):
            bit_in = 1
            while bit_in < self.q:
                # Extract the next bit of this coefficient (in lsb-first order)
                next_bit = (H[x] // bit_in) % 2

                # Insert that bit into the output (in lsb-first order)
                next_val = next_val + next_bit * bit_out

                # And update variables to make sure things go in the right
                # order
                bit_in = 2*bit_in
                bit_out = 2*bit_out

                # If we've filled up this output byte, insert it onto the
                # output string
                if bit_out == 256:
                    list.append(next_val)
                    bit_out = 1
                    next_val = 0

        # And if we have a partial byte, insert that into the output string
        # as well
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
        sum = 0
        while total_bytes < self.n-1:

            # Extract the next bit of the string (in lsb-first order)
            next_bit = (list[x] // bit_in) % 2

            # Insert that bit into the next coefficient (in lsb-first order)
            next_val = next_val + next_bit * bit_out

            # Step to the next input bit
            bit_in = 2*bit_in
            if bit_in == 256:
                x = x + 1         # Ran out of bits in this byte; step to
                bit_in = 1        # the next byte

            # Step to the next output bit
            bit_out = 2*bit_out

            # If we've filled the coefficent, append it to the list
            if bit_out == self.q:
                H.append(self.modq(next_val))
                total_bytes = total_bytes+1

                # We track the sum of all the coefficients
                sum = sum + next_val

                # And start on the next coefficient
                bit_out = 1
                next_val = 0

        # Reconstruct the last coefficent; it's minus the sum of all the
        # coefficients we did read (for polynomials that are multiples of
        # x-1, the sum of the coefficients is 0)
        H.append(self.modq(-sum))
        return H

    # Pack a trinary polynomial (one whose elements are all 0, 1, -1)
    # into a bytestring.
    # If there's an element of A that's not 0, 1 or -1, then it doesn't
    # matter what we map it to - this output will end up being ignored
    def pack_S3(self, A):
        list = bytearray()
        num_byte = 0          # The next byte to output to the string
        mult = 1              # Where the next element goes within the
                              # next byte
        collected = 0         # The number of coefficients we have
                              # inserted into this next byte
        for x in range(self.n-1):
               # Grab the next coefficient and add it into the buffer
               # in ls-trit first order
               val =  A[x]
               val = val % 3   # We encode -1 elements as '2'
               num_byte = num_byte + mult*val
               mult = 3*mult
               collected = collected + 1

               # If we've collected 5 coefficients, or we hit the lsat
               # coefficient, deposit the byte we have
               if collected == 5 or x == self.n-2:
                   list.append(num_byte)
                   num_byte = 0
                   mult = 1
                   collected = 0
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
        C = self.add( self.multiply( R, H ), M )

        # And that's the ciphertext (converted into the 'on-the-wire'
        # format)
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
    #       polynomial).  This is here so that we could have a method to
    #       reexport the public key (which we don't have at the moment)
    #  - H_inv, which is H^-1; not secret, but is useful during decryption
    #  - F_inv, which is F^-1 (computed over modulo 3)
    #  - S, which is a random 32 byte string; it is used to disguise
    #       decryption failures

    #
    # This is the key generation routine; it returns the public key
    def key_gen(self):
        # Select small F, G parameters
        self.F = self.sample_iid()
        G = self.sample_fixed_type()

        # Multiply G by 3 (because, during decryption, we'll take
        # things modulo 3, which will cause multiples of 3G to fall out)
        G = self.multiply_int(G, 3)

        # And construct the public key
        FG = self.multiply(self.F, G)    # FG = F*G
        FG_inv = self.invert(FG)         # FG_inv = (F*G)^-1

        # H = F^-1 * G
        # This is the public key
        self.H = self.multiply(self.multiply(FG_inv, G), G)

        # H_inv = F * G^-1
        # This is computable from the public key; we use it to
        # speed up the decryption process
        self.H_inv = self.multiply(self.multiply(FG_inv, self.F), self.F)

        # F_inv = F^-1 (but this time, over polynomials modulo 3)
        self.F_inv = self.invert_3(self.F)

        # And select the random S string (used to disguise KEM failure)
        self.S = bytearray()
        for _ in range(32):
            self.S.append( random.randrange(256) )

        # And return the public key
        return self.pack_Rq0(self.H)

    #
    # Check if M is a legal value; return 0 if it is, a nonzero 16 bit
    # value if it is not
    # In this case, legal means it is a possible output of sample_fixed_type,
    # that is, it consists of q/16-1 1's, q/16-1 -1's and the rest are 0
    # (and the last element is always 0)
    # This changes for HRSS
    def check_m(self, M):
        failure = M[self.n-1]    # We set failure to nonzero if any error
                                 # is detected
        count_1 = 0              # The number of 1's minus the number of -1's
        count_2 = 0              # Twice number of -1's counted
        for x in range(self.n-1):
            v = M[x]
            count_1 = count_1 + v  # Increment if v=1, decrement if v=-1
            count_2 = count_2 + (v & 2) # Double Increment count_2 if v is -1

            # We also set failure if v is not -1,0,1
            failure = failure | ((v+1) & 0xfffc) # Fail if v not [-1,0,1,2]
            failure = failure | ((v+2) & 0xfffc) # Fail if v not [-2,-1,0,1]

        # Mark failure if we didn't see precisely q/16-1 -1's
        failure = failure | (count_2 - 2*(self.q//16 - 1))

        # Mark failure if we didn't see the same number of 1's and -1's
        # If we passed the previous test, there must be q/16-1 -1's, and hence
        # there must also have been q/16-1 1's
        failure = failure | count_1

        return failure
    
    #
    # Check if R is a legal value; return 0 if it is
    # In this case, legal means it is a possible output of sample_iid,
    # that is, 'all values either 0, 1 or -1' and the last element 0
    def check_r(self, R):
        failure = 0          # We set failure to nonzero if any error
                             # is detected
        for x in range(self.n-1):
            v = R[x]
            # failure will remain 0 if the value is in the range (-1, 0, 1, 2)
            failure = failure | ((v+1) & 0xfffc)
            # t will remain 0 if the value is in the range (-2, -1, 0, 1)
            failure = failure | ((v+2) & 0xfffc)

        # The last coefficient must also be 0
        failure = failure | R[self.n-1]

        return failure

    #
    # This is the deterministic public key decryption routine
    # It should not be called directly by the application
    def decrypt(self, C):
        # Step one is supposed to check if C = 0 mod x-1; however because
        # of how the unpack_Rq0 logic works, that is always true

        # Compute A = C*F, which is R*G + M*F assuming the encryptor was legit
        A = self.multiply(C, self.F)

        # Compute A*F^{-1} mod 3; every element of R*G is a multiple of 3, and
        # so this is M*F*F^{-1} = M (mod 3), assuming the encryptor was legit
        M = self.multiply_3(A, self.F_inv)

        # So, if the ciphertext is valid, then M is the same value the
        # encryptor selected

        # If we do HRSS, this changes
 
        # Reconstruct the encryptor's R by computing (C-M)*H^{-1}
        CMP = self.subtract( C, M )
        R = self.multiply( CMP, self.H_inv )
        R = self.mod_phin(R)   # self.H_inv was computed modulo (x^n-1)/(x-1)
                               # scrub off the multiple of x-1 that may remain

        # Check if R, M is a legal value
        # If this was an invalid ciphertext, these will not be legit
        failure_flag = self.check_m(M)
        failure_flag = failure_flag | self.check_r(R)

        return (R,M,failure_flag)
 
    #
    # This is the KEM decapsulate routine; it is passed the key share and
    # returns a shared secret (either the valid one, or an error one)
    def kem_decapsulate(self, C_packed):

        # Recover the ciphertext that the encryptor sent
        C = self.unpack_Rq0(C_packed)

        # Recover the R, M values (and whether the decryption suceeded)
        (R, M, failure_flag) = self.decrypt(C)

        # Hash the R, M values together (which will be the same shared secret
        # that the encryptor selected on a valid encryption)
        K1 = self.hash_two_trinary_polynomials(R, M)

        # Hash the ciphertext and a random value; this is a random looking
        # string that we return on decryption failure.  And, since this
        # depends only on the ciphertext, we'll always get the same random
        # string even if they submit the same ciphertext
        K2 = hash_two_strings(self.S, C_packed)

        # On success, return the real shared secret.  On failure, return the
        # decoy.
        # This code sets result to K1 on success, K2 on failure
        failure_flag = failure_flag | -failure_flag  # Bit 15 set on failure
        bad_mul = (failure_flag >> 15) & 1  # 1 on failure, 0 on success
        good_mul = 1-bad_mul                # 1 on success, 0 on failure
        result = bytearray()
        for x in range(32):
            result.append( good_mul*K1[x] + bad_mul*K2[x] )

        return result

#
# So that's our NTRU implementation; now we get to the demonstration code
# which uses it
#
# Here is a quick example; a key exchange between Alice and Bob
# The convention this uses is: everything Alice owns is prefixed by 'a_'
# Everything Bob owns is prefixed by 'b_'
# parameter_set = 'hps2048509'
parameter_set = 'hps2048677'
# parameter_set = 'hps4096821'
# parameter_set = 'tiny'

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
