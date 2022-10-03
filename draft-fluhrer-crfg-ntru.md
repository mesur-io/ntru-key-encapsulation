%%%
title: "NTRU Key Encapsulation"
category: info

docname: draft-fluhrer-crfg-ntru-latest
submissiontype: IETF 
number:
date:
consensus: true
v: 3

# area: SEC
# workgroup: CFRG
keyword:
 - NTRU
 - post quantum
 - kem
venue:
#  group: CFRG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
  github: "mesur-io/ntru-key-encapsulation"
  latest: "https://mesur-io.github.io/ntru-key-encapsulation/draft-fluhrer-crfg-ntru.html"

author:
 -
    fullname: Scott Fluhrer
    organization: Cisco Systems
    email: "sfluhrer@cisco.com"

author:
 -
    fullname: Michael Prorock
    organization: mesur.io
    email: "mprorock@mesur.io"


normative:

informative:


# Abstract

This draft documents NTRU as a method for post quantum key encapsulation mechanism (KEM).  The NTRU method from KEM is believed to be IPR free and cryptogprahically sound for both pre and post quantum threat environments.

NIST has run a competition to select postquantum primitives and selected Kyber for KRM.  Kyber unfortunately has plausible patent claims against it and there are currently undisclosed agreements with the patent holders and NIST. It is unknown whether those agreements would be universally acceptable; if not, there will be organizations for which Kyber is unusable until the patents expire.

This document does not define any new cryptography, only describes an existing cryptographic system.

# Introduction

This document describes the key encapsulation mechanism (KEM) based on Hoffstein, Pipher, and Silverman's NTRU encryption scheme, commonly referred to as NTRU. NTRU is constructed by utilization of a correct deterministic public key scheme (correct DPKE).  The method described here is based on a combination of prior approaches described in NTRUEncrypt and NTRU-HRSS-KEM (as submitted to Round 3 of the NIST PQC project), and permits use of four well defined and reviewed parameter sets.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Notation

# Parameter sets

NTRU parameter sets define both the size of the vectors (refered to as polynomials) used within NTRU, as well as the modulus Q used in internally.  This document defines two parameter sets, one called hps2048677, which has Q=2048 and N=677 and another called hps4096821, which has Q=4096 and N=821.

# Cryptographic Dependencies

## Polynomials

NTRU is based on polynomials; these can be viewed as a vector of N small values (either between 0 and Q-1, or sometimes either 0, 1 or -1), where the values of both N and Q are specified by the parameter set.  In all parameter sets, Q is less than 65536, hence each small value fits within a 16 bit value.

Each polynomial is an array of values a(n-1), a(n-2), ..., a(0), with the implicit polynomial being
a(n-1)x^(n-1) + a(n-2)x^(n-2) + ... + a(2)x^2 + a(1)x + a(0) (where x is an artificial variable that doesn't take a specific value).
When we multiply two polynomials, we first do it as we do in standard algebra; we multiply each pair of terms (including x exponential), and then sum the products which have the same resulting x term.  For example, (2x^2 + 3x + 5)(4x + 8) = (2*4)x^3 + (2*8 + 3*4)x^2 + (3*8 + 4*5)x + 5*8 = 8x^3 + 28x^2 + 44x + 40.

For NTRU, however, we do two additional reductions to this multiplication.  First, for each sum of the product, we compute that sum modulo a constant factor (either 3 or the value Q; NTRU uses both at times).  In the above example, if we were reducing things modulo 3, we would actually get the resulting polynomial (8 mod 3)x^3 + (28 mod 3)x^2 + (44 mod 3)x + (40 mod 3) = 2x^3 + x^2 + 2x + 1.

In addition, we compute the multiplication modulo x^n - 1 (where the value of n is specified in the parameter set); that is, we subtract multiples of x^n-1 until the result is a
polynomial of degree n-1 or less.
An equivalent way of expressing this is to add the resulting coefficent to the term x^(i+n) to the coefficent to the term x^i (modulo the constant factor), and then discard all terms x^n and above.

In the above example, assuming n=2, the final result would be (2+2 mod 3)x + (1+1 mod 3) = x + 2.

A polynomal can be conveniently represented by an array of n values (with the x^i factor being implicit in the positions in the array); 16 bits per value are sufficient to represent all the coefficients that are encountered within NTRU.

For most polynomials A = a(n-1)x^(n-1) + a(n-2)x^(n-2) + ... + a(0),
there is a second polynomial B = b(n-1)x^(n-1) + b(n-2)x^(n-2) + ... + b(0), such that when we multiply A and B together
(and do the above reductions), we end up with the polynomial 1 = 0x^(n-1) + 0x^(n-2) + ... + 0x + 1.
We state this relationship as B = inv(A).

Inverses can be computed efficiently, and also have the property that similar polynomials have inverses that are quite different.

## Polynomial Addition

[Now, I have working python code in ntru.py; should we just refer to that code, or bring in selected portions
into this document?  I expect we don't want the preliminary versions of the code I wrote here...]

When NTRU adds two polynomials, it does it by adding each element of the vector independently modulo Q.  In Python, this could look like:

~~~
def polynomial_add(a, b):
		sum = [ ]
		for x in range(n):
			 sum[x] = (a[x] + b[x]) % q
		return sum 
~~~

## Polynomial Subtraction

When NTRU subtracts two polynomials, it does it by subtracting each element of the vector independently modulo Q; that is, if the subtraction of two elements results in a negative value, it adds Q to the difference.  In Python, this could look like:

~~~
def polynomial_subtract(a, b):
		sum = [ ]
		for x in range(n):
			 sum[x] = (a[x] + q - b[x]) % q
		return sum 
~~~

## Polynomial Multiplication

When NTRU multiplies two polynomials, it does it by multiplying each pair of elements from each polynomial, and adding that result to the element indexed by the sum of the indicies (wrapping around if the sum is N or more).  In Python, this could look like:

~~~
	def polynomial_multiply(a, b):
		 product = []
		 for x in range(n)
			  product[x] = 0
		 for x in range(n)
			  for y in range(n)
				   z = (x + y) % n
			    product[z] = (product[z] + a[x]*b[y]) % q
		 return product
~~~

Note that this is example code; in many cases, one of the polynomials will be light weight (that is, has many element of 0), and more efficient algorithms may be available.

Q: at one point, NTRU does polynomial multiplication modulo phi_N, 3 - have do we document that?

## Polynomial Inversion

When NTRU 'inverse a polynomial' X, it finds a polynomial Y such that polynomial_multiply(X, Y) gives the polynomial (1, 0, 0, 0, ..., 0).

Here, give the algorithm to invert a polynomial.

# Selecting Random Polynomials

When running NTRU, we need at times random polynomials with specific forms; doing this is referred to a sampling.
We need to do this both when generating keys as well as when encrypting a message.
It MUST rely on a cryptographically secure random number generator to select these values.

## Sample a random trinary polynomial

This function (called sample_iid by the reference code) selects a random trinary polynomial,
that is, one whose coefficients are all either 0, 1 or 2, with the last coefficient 0.

This can be done by calling the rng n-1 times to generate n-1 bytes, and then taking each byte modulo 3 (and setting the last coefficient to be 0).
This isn't precisely uniform; it is close enough for security.

## Sample a random balanced trinary polynomial

This function (called sample_fixed_type by the refence code) selects a random trinary sample with a specific weight; it consists of q/16-1 cofficients which are 1, q/16-1 coefficients which are -1, and the remainder (which includes coefficient n) as 0.

This can be done by generating n-1 random values; tagging q/16-1 of the values as 1; q/16-1 of the values as -1 and the rest tagged as 0.  Then, you can sort (in constant time) the random values; the resulting tags are in the required random order.

# Converting Between Polynomials and Byte Strings

NTRU needs to convert polynomials into byte strings and vica versa,
both the export public keys and ciphertexts, as well as being able to hash those polynomials.
We refer to this process as serialization and deserialization.

## Serialize a polynomial base q

This function (called pack_Rq0 by the reference code) converts a polynomial into a byte string.

This function takes the first n-1 coefficients (each a value between 0 and q-1), expresses each
as a log_2(q) bit bit string as a little endian integer.
Then, it concatinates those n-1 bit strings into a long bit string; the result
is that bit string being parsed into bytes (with any trailing bits in the last byte being set to 0).

The inverse function (called) unpack_Rq0) converts that byte string back into a polynomial.

It takes the byte string, parses it into n-1 consecutive log_2(q) bit strings, takes each such
bit string as a little endian integer and sets the corresponding coefficient of the polynomial to
that integer.  Then, it adds all those n-1 coefficients together, and sets the n-th coefficient
to the negation of that sum modulo q.

A close reading of the above algorithms will note that the pack_Rq0 doesn't actually depend on the
last coefficient.  This is because this code assumes that the polynomial is a multiple of the
polynomial x-1; the unpack_Rq0 code uses that assumption to reconstruct that last coefficient.

This assumption is true within NTRU because pack_Rq0 will be called only for polynomials that
are a multiple of the polynomial G; we always sample G values that have an equal number of 1 and
-1 coefficients (with the rest 0), and any such polynomial will always be a multiple of x-1.

## Serialize a trinary polynomial

This function (called pack_S3 by the reference code) converts a trinary polynomial into a byte string.

This function takes the n-1 coefficients in sets of 5; it converts the five coefficients c0, c1, c2, c3, c4 into the values 0, 1 or 2.
This it sums up the coefficients as c0 + 3*c1 + 9*c2 + 27*c3 + 81*c4, and then stores that value as the next byte in the byte string.

If the last set of 5 is incomplete (which will happen if n-1 is not a multiple of 5), then the higher missing coefficients are assumed to be zero.

Now, if the polynomial happens to not be trinary, then it doesn't matter what byte we store; we need to store some value, and this code still needs to be constant time.
The reason we don't care is this happens only on decryption failure (someone handed us an invalid ciphertext); in that case, the value of the hash will end up being ignored.
Of course, no matter what the coefficient is, this still needs to be done in constant time.

This output of this function will be used only for hashing, hence there is no need for an inverse function.

# NTRU Encryption

## Overview

Here is a simplified overview how NTRU works (omitting some of the necessary tests used to address active attacks).

To generate a public/private keypair,
Alice selects two 'short' polynomials F and G (where short means that the coefficients are all 0, 1 or q-1).
She then multiplies each coefficient of G by 3, and then computes H = Inv(F) x G; that is the public key.
She stores F in the private key, and computes Inv(F) (with this inverse taken over the modulo 3 polynomial), and stores that in the private key as well. 
She also computes Inv(H), and stores that in the private key.

To generate a KEM key share with the public key H, Bob selects two short polynomials R and M, and compute C = R x H + M; that is the ciphertext.
Bob also hashes R and M to generate his copy of the shared secret.

When Alice receives C = R x Inv(F) x G + M, she first multiplies that by F; this results in C x F = R x G + M x F.
Since all the polynomials R, G, M, F are short, the resulting coefficients are not large (that is, always less than Q/2),
and so the fact that we computed everything modulo Q can be ignored.
Then, she take all the coefficients modulo 3; because all the coefficients of G are multiples are 3 (and so is R x G), those drop out, and Alice is left with M x F (with each coefficient taken modulo 3).
She then multiples that polynomial by Inv(F) (this time over the modulo 3 polynomial), recovering M.
She then uses M, the original ciphertext and the stored value Inv(H) to recover R.
She then hashes R and M together to generate her copy of the shared secret.

Assuming Bob received Alice's public key H correctly, and Alice recieved Bob's ciphertext C correctly, they will derive the same shared secret.

## Private and Public Key Generation

To generate a public/private keypair, we can follow this procedure:

- Sample a random F using the sample_iid procedure

- Sample a random G using the sample_fixed_type procedure

- Multiply each coefficient of G by 3

- Compute FG_inv = Inverse( F * G ) (this computation is done modulo q)

- Compute H = FG_inv * G * G (modulo q)

- Compute H_inv = FG_inv * F * F (modulo q)

- Compute F_inv = Inverse( F ) (this computation is done modulo 3)

- Sample a random 32 byte value S randomly

The resulting public key is the value H (serialized by the pack_Rq0 procedure); the resulting private key are the values F, H_inv, F_inv and S.  Any other intermediate values should be securely disposed.
 
# Parameter Sets

~~~
+================+====================+===========+
| Parameter Set  | Polynomial Size N  | Modulus Q |
+================+====================+===========+
| ntruhps2048509 |         509        |    2048   |
+----------------+--------------------+-----------+
| ntruhps2048677 |         677        |    2048   |
+----------------+--------------------+-----------+
| ntruhps4096821 |         821        |    4096   |
+----------------+--------------------+-----------+
~~~

[Question: do we want to support the ntruhrss701 parameter set?  I'm thinking not, because as far as I
can see, that doesn't actually bring anything to the table (while adding complication) - ntruhps2048677 appears to be smaller/more secure and the performance delta is not that large]

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
