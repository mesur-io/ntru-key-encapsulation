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

In the python examples, we will have n and q be global variables; python code to set these globals appropriately might be:

~~~
def set_parameter_set_hps2048677():
  global n
  n = 677
  global q
  q = 2048
def set_parameter_set_hps4096821():
  global n
  n = 821
  global q
  q = 4096
~~~

One of the above two routines should be called before any NTRU operations.

# Cryptographic Dependencies

## Polynomials

NTRU is based on polynomials; these can be viewed as a vector of N small values (between 0 and Q-1, or alternatively between -Q2 and Q/2-1), where the values of both N and Q are specified by the parameter set.  In all parameter sets, Q is less than 65536, hence each small value fits within a 16 bit value.

Each polynomial is an array of values a(n-1), a(n-2), ..., a(0), with the implicit polynomial being
a(n-1)x^(n-1) + a(n-2)x^(n-2) + ... + a(0) (where x is an artificial variable that doesn't take a specific value).
When we multiply two polynomials, we compute the product of the two polynomials as normal (reducing each coefficient
by the constant factor, either 3 or the value Q), and then we subtract multiples of x^n-1 until the result is a
polynomial of degree n-1 or less.

In addition, for most polynomials A = a(n-1)x^(n-1) + a(n-2)x^(n-2) + ... + a(0),
there is a second polynomial B = b(n-1)x^(n-1) + b(n-2)x^(n-2) + ... + b(0), such that when we multiply A and B together
(and doing the above reductions), we end up with the polynomial 1.
We state this relationship as B = inv(A).

Inverses can be computed efficiently, and also have the property that similar polynomials have inverses that are quite different.

## Polynomial Addition

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

# Algorithm Identifiers

ntruhps2048509
ntruhps2048677
ntruhrss701
ntruhps4096821

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
