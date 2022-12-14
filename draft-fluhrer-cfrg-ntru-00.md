%%%
title = "NTRU Key Encapsulation"
abbrev = "NTRU"
ipr = "trust200902"
area = "Internet"
workgroup = "CFRG"
submissiontype = "IETF"
keyword = ["NTRU", "post quantum", "kem"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-fluhrer-cfrg-ntru-latest"
stream = "IETF"
status = "informational"

[pi]
toc = "yes"

[[author]]
initials = "S."
surname = "Fluhrer"
fullname = "Scott Fluhrer"
organization = "Cisco Systems"
  [author.address]
  email = "sfluhrer@cisco.com"

[[author]]
initials = "S."
surname = "Prorock"
fullname = "Michael Prorock"
organization = "mesur.io"
  [author.address]
  email = "mprorock@mesur.io"

[[author]]
initials = "M."
surname = "Celi"
fullname = "Sofia Celi"
organization = "Brave"
  [author.address]
  email = "cherenkov@riseup.net"

[[author]]
initials = "J."
surname = "Gray"
fullname = "John Gray"
organization = "Entrust"
  [author.address]
  email = "john.gray@entrust.com"
%%%

.# Abstract

This draft documents NTRU as a post-quantum Key Encapsulation Mechanism (KEM)
scheme. The NTRU method from KEM is believed to be IPR free and
cryptographically sound for both classical and post-quantum threat environments.

NIST has run a competition to select post-quantum primitives and preliminary
selected Kyber for standarization as a KEM.  Kyber unfortunately has plausible
patent claims against it and there are currently undisclosed agreements with the
patent holders and NIST. It is unknown whether those agreements would be
universally acceptable; if not, there will be organizations for which Kyber is
unusable until the patents expire.  This lack of clarity around licensing or
other restrictions on Kyber has provided the motivation to author this draft.

This document does not define any new cryptography, only describes an existing
cryptographic system.

{mainmatter}

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Notational Conventions

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**", "**SHOULD**",
"**SHOULD NOT**", "**RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this
document are to be interpreted as described in [@!RFC2119].

# Terminology

The following functions, terminology and notation are used throughout the
document.

- For any object `x`, we write `len(x)` to denote its length in bytes.
- For two byte arrays `x` and `y`, write `x || y` to denote their
  concatenation.
- I2OSP(x, xLen): Converts a non-negative integer `x` into a byte array of
  specified length `xLen` as described in {{!RFC8017}}. Note that this function
  returns a byte array in big-endian byte order.
- `n` and `q` are coprime positive integers. The first defines the size of the
   polynomials (treated as a zero indexed arrays), and the latter refers to the
   modulus.

# Introduction

This document describes the key encapsulation mechanism (KEM) scheme based on
Hoffstein, Pipher, and Silverman's NTRU encryption scheme, commonly referred to
as NTRU. NTRU is constructed from a deterministic public key scheme (correct
DPKE) into a KEM (which has tight proof of IND-CCA2 security in a classical and
quantum model).  The method described here is based on a combination of prior
approaches, which eventually merged into the NTRUEncrypt and NTRU-HRSS-KEM
submissions (as submitted to Round 2 of the NIST PQC project). The algorithm
described here is based on the Round 3 submission and permits the use of three
well defined and reviewed parameter sets.

# Parameter sets

We define three parameter sets:

## NTRU-HPS 2048509

- Type: HPS
- N: 509
- Q: 2048
- Hash: SHA3-256.
- ID: 0x0001

## NTRU-HPS 2048677

- Type: HPS
- N: 677
- Q: 2048
- Hash: SHA3-256.
- ID: 0x0002

## NTRU-HPS 4096821

- Type: HPS
- N: 821
- Q: 4096
- Hash: SHA3-256.
- ID: 0x0003

# Cryptographic Dependencies

## Polynomials

NTRU is based on polynomials; these can be viewed as a vector of N small values
(either between 0 and Q-1, or sometimes either 0, 1 or -1), where the values of
both N and Q are specified by the parameter set.  In all parameter sets, Q is
less than 65536, hence each small value fits within a 16 bit value.

Each polynomial is an array of values a(n-1), a(n-2), ..., a(0), with the
implicit polynomial being
a(n-1)x^(n-1) + a(n-2)x^(n-2) + ... + a(2)x^2 + a(1)x + a(0)
(where x is an independent variable that doesn't take a specific value).
In this case, we don't think of a polynomial as a function of x that we can
evaluate; instead, it is a quantity in and of itself.

When we multiply two polynomials, we first do it as we do in standard algebra;
we multiply each pair of terms (including x exponential), and then sum the
products which have the same resulting x term.  For example,
(2x^2 + 3x + 5)(4x + 8) =
(2\*4)x^3 + (2\*8 + 3\*4)x^2 + (3\*8 + 4\*5)x + 5\*8 = 8x^3 + 28x^2 + 44x + 40.

For NTRU, however, we do two additional reductions to this multiplication.
First, for each sum of the product, we compute that sum modulo a constant factor
(either 3 or the value Q; NTRU uses both at times).  In the above example, if we
were reducing things modulo 3, we would actually get the resulting polynomial (8
mod 3)x^3 + (28 mod 3)x^2 + (44 mod 3)x + (40 mod 3) = 2x^3 + x^2 + 2x + 1.

In addition, we compute the multiplication modulo x^n - 1 (where the value of n
is specified in the parameter set); that is, we subtract multiples of x^n-1
until the result is a polynomial of degree n-1 or less. An equivalent way of
expressing this is to add the resulting coefficent to the term x^(i+n) to the
coefficent to the term x^i (modulo the constant factor), and then discard all
terms x^n and above.

In the above example, assuming n=2, the final result would be (2+2 mod 3)x +
(1+1 mod 3) = x + 2.

A polynomal can be conveniently represented by an array of n values (with the
x^i factor being implicit in the positions in the array); 16 bits per value are
sufficient to represent all the coefficients that are encountered within NTRU.

For most polynomials A = a(n-1)x^(n-1) + a(n-2)x^(n-2) + ... + a(0), there is a
second polynomial B = b(n-1)x^(n-1) + b(n-2)x^(n-2) + ... + b(0), such that when
we multiply A and B together (and do the above reductions), we end up with the
polynomial 1 = 0x^(n-1) + 0x^(n-2) + ... + 0x + 1. We state this relationship as
B = inv(A).

Inverses can be computed efficiently, and also have the property that similar
polynomials have inverses that are quite different.

### Trinary Polynomials

Some of the polynomials that NTRU uses are 'trinary polynomials'.
These are standard polynomials that have all their coefficients being either 0, 1 or Q-1.
The standard operations (including polynomial multiplication and inversion) can be done the same.
However, an implementation may decide to optimize some operations based on a specific polynomial being trinary.

## Polynomial Addition

When NTRU adds two polynomials, it does it by adding each element of the vector
independently modulo Q.

## Polynomial Subtraction

When NTRU subtracts two polynomials, it does it by subtracting each element of
the vector independently modulo Q; that is, if the subtraction of two elements
results in a negative value, it adds Q to the difference.

## Polynomial Multiplication

When NTRU multiplies two polynomials, it does it by multiplying each pair of
elements from each polynomial, and adding that result to the element indexed by
the sum of the indicies (wrapping around if the sum is N or more).

Note that this can be optimized; in many cases, one of the polynomials will be
of special form (for example, consists of only 0, 1 and -1), more efficient
algorithms may be available.

## Polynomial Inversion

When NTRU 'inverts a polynomial' X, it finds a polynomial Y such that
polynomial_multiply(X, Y) gives the polynomial 0x^(n-1) + 0x^(n-2) + ... + 0x^2 + 0x^1 + 1 = (1, 0, 0, 0, ..., 0).

## Computing a Polynomial Modulo (x^n-1)/(x-1)

At one point, we need to take a polynomial modulo x^(n-1)+x^(n-2)+...+1 =
(x^n-1)/(x-1). We refer to this operation as modPhiN, and can be performed by
taking the top coefficient, and subtracting it from all the other coefficients.

# Selecting Random Polynomials

When running NTRU, we need at times random polynomials with specific forms;
doing this is referred to a sampling.

We need to do this both when generating keys as well as when encrypting a
message. It MUST rely on a cryptographically secure random number generator to
select these values.

## Sample a random trinary polynomial

This function (called sample_iid in the reference code) selects a random trinary
polynomial, that is, one where all the coefficients are either 0, 1 or q-1, with
 the last coefficient 0.

This operation is performed by calling the rng n-1 times to generate n-1 bytes,
and then taking each byte modulo 3, mapping 2 to q-1 (and setting the last
coefficient to be 0) While this operation is not precisely uniform, it is close
enough for the purposes of NTRU.

## Sample a random balanced trinary polynomial

This function (called sample_fixed_type by the reference code) selects a random
trinary sample with a specific weight; it consists of q/16-1 cofficients which
are 1, q/16-1 coefficients which are q-1, and the remainder (which includes
coefficient n) as 0.

This can be done by generating n-1 random values; tagging q/16-1 of the values
as 1; q/16-1 of the values as q-1 and the rest tagged as 0.  Then, you can sort
(in constant time) the random values; the resulting tags are in the required
random order.  You then scan through the list, and assign the coefficients to
the values of the tags.

# Validating polynomials

We also need to validate polynomials generated during decapsulation; that is,
whether they were possible outputs of the sample_iid or sample_fixed_type
procedures.

## ValidR

This verifies that R is a possible output of the sample_iid procedure; that is,
that the coefficients of the polynomial R consists only of 0, 1 and q-1, and
that the last coefficient is 0.

## ValidM

This verifies that M is a possible output of the sample_fixed_type procedure;
that is, that the coefficients of the polynomial R consists only of 0, 1 and
q-1, that the last coefficient is 0, and that there are precisely q/16-1 1
values and q/16-2 q-1 values.

# Converting Between Polynomials and Byte Strings

NTRU needs to convert polynomials into byte strings and vice versa, both to
export public keys and ciphertexts, as well as being able to hash those
polynomials. We refer to this process as serialization and deserialization.

## Serialize a polynomial base q

This function (called pack_Rq0 by the reference code) converts a polynomial into
a byte string.

This function takes the first n-1 coefficients (each a value between 0 and q-1),
expresses each as a log_2(q) bit bitstring as a little endian integer.  All n-1
coefficients are of length log_2(q).  Then, it concatinates those n-1 bit strings
into a long bit string; the result is that bit string being parsed into bytes
(with any trailing bits in the last byte being set to 0).

The inverse function (called) unpack_Rq0) converts that byte string back into a
polynomial.

It takes the byte string, parses it into n-1 consecutive log_2(q) bit strings,
takes each such bit string as a little endian integer and sets the corresponding
coefficient of the polynomial to that integer.  Since all bit strings are of equal
length, this can be done efficiently.  Then, it adds all those n-1 coefficients
together, and sets the n-th coefficient to the negation of that sum
modulo q.

A close reading of the above algorithms will note that the pack_Rq0 doesn't
actually depend on the last coefficient.  This is because this code assumes that
the polynomial is a multiple of the polynomial x-1; the unpack_Rq0 code uses
that assumption to reconstruct that last coefficient.

This assumption is true within NTRU because pack_Rq0 will be called only for
polynomials that are a multiple of the polynomial G; we always sample G values
that have an equal number of 1 and -1 coefficients (with the rest 0), and any
such polynomial will always be a multiple of x-1.

## Serialize a trinary polynomial

This function (called pack_S3 by the reference code) converts a trinary
polynomial into a byte string.  It works by taking the coefficients in
groups of 5, and packing each such group into a byte.

This function takes the n-1 coefficients in sets of 5; it converts the five
coefficients c0, c1, c2, c3, c4 into the values 0, 1 or 2. Then it sums up the
coefficients as c0 + 3*c1 + 9*c2 + 27*c3 + 81*c4, and then stores that value as
the next byte in the byte string.

If the last set of 5 is incomplete (which will happen if n-1 is not a multiple
of 5), then the higher missing coefficients are assumed to be zero.

Now, if the polynomial happens to not be trinary, then it doesn't matter what
byte we store; we need to store some value, and this code still needs to be
constant time. The reason we don't care is this happens only on decryption
failure (someone handed us an invalid ciphertext); in that case, the value of
the hash will end up being ignored. Of course, no matter what the coefficient
is, this still needs to be done in constant time.

This output of this function will be used only for hashing, hence there is no
need for an inverse function.

# NTRU

## Overview

This section provides a simplified overview how NTRU works. Minor details are
omitted for clarity reasons, and the Security Considerations section should be
consulted prior to implementation.

To generate a public/private keypair, Alice selects two 'short' polynomials F
and G (where short means that the coefficients are all 0, 1 or q-1). She then
multiplies each coefficient of G by 3, and then computes H = Inv(F) x G; that is
the public key. She stores F in the private key, and computes Inv(F) (with this
inverse taken over the modulo 3 polynomial), and stores that in the private key
as well. She also computes Inv(H), and stores that in the private key.

To generate a KEM key share with the public key H, Bob selects two short
polynomials R and M, and computes C = R x H + M; that is the ciphertext. Bob also
hashes R and M to generate his copy of the shared secret.

When Alice receives C = R x Inv(F) x G + M, she first multiplies that by F; this
results in C x F = R x G + M x F. Since all the polynomials R, G, M, F are
short, the resulting coefficients are not large (that is, always less than Q/2
in absolute value), and so the fact that we computed everything modulo Q can be
ignored. Note that some of the coefficients may be 'negative' (that is, in the
range Q/2 to Q-1); those need to be treated as negative values for this next
step. Then, she take all the coefficients modulo 3 (taking into account the
negative coefficients); because all the coefficients of G are multiples are 3
(and so is R x G), those drop out, and Alice is left with M x F (with each
coefficient taken modulo 3). She then multiples that polynomial by Inv(F) (this
time over the modulo 3 polynomial), recovering M. She then uses M, the original
ciphertext and the stored value Inv(H) to recover R. She then hashes R and M
together to generate her copy of the shared secret.

Assuming Bob received Alice's public key H correctly, and Alice recieved Bob's
ciphertext C correctly, they will derive the same shared secret.

## Private and Public Key Generation

To generate a public/private keypair, we can follow this procedure:

- Generate a random polynomial f using using the ``sample_iid`` procedure.
- Generate a random polynomial g using the the ``sample_fixed_type`` procedure
- Multiply each coefficient of g by 3.
- Compute FG_inv = Inverse( f * g  mod q)  mod q.
- Compute H = FG_inv * g * g (modulo q)
- Compute H_inv = FG_inv * f * f (modulo q)
- Compute F_inv = Inverse( f ) (this computation is done modulo 3)
- Generate a random 32 byte value s randomly

The resulting public key is the value H (serialized by the pack_Rq0 procedure);
the resulting private key are the values F, H_inv, F_inv and S.  Any other
intermediate values should be securely disposed.

n.b. the initial generation of random polynomials can be combined into a single
procedure

## Key Encapsulation

This takes a public key H, and generates both a ciphertext C as well as a secret
string K. The ciphertext C should be sent to the holder of the private key; the
string K should be used as the secret.

We can follow this procedure:

- Unpack the public key (using the unpack_Rq0 procedure) to obtain the
  polynomial H
- Sample a random R using the sample_iid procedure
- Sample a random M using the sample_fixed_type procedure
- Compute C = R*H + M (perfoming both the polynomial multiplication and
  polynomial addition modulo q)
- Serialize both R and M (using the pack_S3 procedure on both) and use SHA3-256
  to hash the concatination; the resulting 32 bytes is the secret string K
- Return K and C serialized using the pack_Rq0 procedure

## Key Decapsulation

This takes a private key (F, H_inv, F_inv, S) and a ciphertext C, and produces a
secret string K. If the ciphertext is the same as what was proceduced by the key
encapsulation procedure, then this will generate the same secret string K.

We can follow this procedure:

- Unpack the ciphertext (using the unpack_Rq0 procedure) to obtain the polynomial C

- Compute A = C*F (modulo q)

- For each coeffient x in A, if it is < q/2, replace it with x mod 3; if it is
  >= q/2, replace it with 2 - (q-1-x) mod 3

[THIS STEP IS NEEDED BECAUSE WE REPRESENT COEFFICIENTS IN THE RANGE 0..Q-1 -
WOULD A BALANCED REPRESENTATION BE CLEARER?]

- Compute M = A*F_inv (modulo 3) - note the change of moduli

- For each 2 coefficient within M, replace it with q-1

- Compute R = (C - M) * H_inv (modulo q)

- Compute R = modPhiN(R) (modulo q)

- Set Success = ValidM(M) AND ValidR(R)

- Serialize both R and M (using the pack_S3 procedure on both) and use SHA3-256
  to hash the concatination; the resulting 32 bytes is K1

- Use SHA3-256 to hash the concatination of S (from the private key) and C, the
  resulting 32 bytes is K2

- If Success, return K=K1; otherwise, return K=K2

# Parameter Sets

| Parameter Set  | Polynomial Size N  | Modulus Q |
|----------------|--------------------|-----------|
| ntruhps2048509 |         509        |    2048   |
| ntruhps2048677 |         677        |    2048   |
| ntruhps4096821 |         821        |    4096   |

Other parameter sets do exist, such as ntruhrss701, hovewver they are not
supported by this RFC at this time as they introduce complexity without
significant value to security, size or performance.

# Usage

NTRU solves the problem where two systems (we'll call them Alice and Bob) wish
to establish a common secret string that they can use to derive keys to protect
future communication. They share a communication path that is authenticated
(that is, the problem of detecting changes to messages between Alice and Bob is
solved by something else), but that communication path may be monitored. What
NTRU tries to achieve is to ensure that someone monitoring the communication
path cannot rederive the common secret string (and hence cannot derive the
communication keys).

To do this, Alice and Bob follow this three step process

- Step 1: Alice follows the 'Private and Public Key Generation' procedure; this
  creates a private key (which Alice keeps to herself) and a public key, which
  she sends to Bob.  Alternatively, she may decide to reuse a previously
  generated keypair.

- Step 2: Bob receives Alice's public key, and follows the 'Key Encapsulation'
  procedure; this creates a secret string (which Bob keeps to himself) and a
  ciphertext, which he sends to Alice

- Step 3: Alice recieves Bob's ciphertext, and follows the 'Key Decapuslation'
  procedure; this creates a secret string (which Alice keeps to herself).  Alice
  can then either destroy her private key, or keep it around for next time.

The secret strings that Alice and Bob generate are the same, and can be used for
creating symmetric keys or other key shared material used to protect future
communications.

## Comparison with DH

NTRU at first glace appears as though it may be performing the same job as
Diffie-Hellman. In fact, NTRU can be viewed as a drop-in replacement for DH
(with larger key shares) in some protocols. However, the equivalence is not
exact; with NTRU, Bob cannot compute the ciphertext until he possesses the
public key.

In contrast, in Diffie-Hellman, both sides can generate their key share g^x mod
p independently. Some use cases take advantage of this property of
Diffie-Hellman (for example, everyone publishes their key shares in a central
directory; to generate keys with someone else, we can download their public key
from the directory, and obtain the same key as they get when they download our
key from the directory). A protocol that does this is known as a NonInteractive
Key Exchange (NIKE). NTRU does NOT provide NIKE capabilities, and if non
interactive use cases are required to be supported, a different approach should
be selected.

# Security Considerations

Current best practices should be followed, especially in regards to known
plaintext attacks, such as Meet-In-The-Middle (MITM), and known ciphertext
attacks.

Lattice reductions via Lenstra-Lenstra-Lovasz may be possible against NTRU with
weak parameter set selection.

## Parameter set security

In all paramter sets, indistinguishability under adaptive chosen ciphertext
attack (IND-CCA2) is a desired property.

Equivalent bit strengths of the described parameter sets are outlined in the
table below:

| Parameter Set  | Security Model     | Bit Strength |
|----------------|--------------------|--------------|
| ntruhps2048509 | IND-CCA2           |     128      |
| ntruhps2048677 | IND-CCA2           |     192      |
| ntruhps4096821 | IND-CCA2           |     256      |

## Public key reuse

NTRU public/private keys can be safely reused for certain use cases.
Reusing an NTRU key may be tempting, because the NTRU key generation process is
considerably more costly than the key encapsulation or decapsulation operations.
On the other hand, if you do reuse NTRU keys, you lose the Perfect Forward
Secrecy property. That is, as long as you don't zeroize the NTRU private key,
then an attacker that can break into the system can extract that private key,
and then recover any symmetric keys that were negotiated with that private key.

If keys are reused, key revocation mechansims should be considered.

# IANA Considerations

This document has no IANA actions.

# Open Questions

- HRSS - currently, we omit that parameter set - it does perform slightly faster
  than the HPS parameter set at the same security level (at the cost of a larger
  public key/ciphertext).  My expectation is that the larger keyshare size for
  HRSS is a more significant cost than the larger computational cost for HPS.
  It would also complicate the logic somewhat (as we would need to specify both
  the HPS and the HRSS ways of doing things).  Is the decision to leave it out
  the correct one?

- We don't specify a flattened format for a private key.  In my view, there is
  no need; systems will generally use ephemerial public/private key pairs, that
  is, create them on the fly, use them for one or a handful of exchanges and
  then throw them away.  In this use case, there is no need to transfer a
  private key to another device.  Now, it is possible for NTRU to be used with
  static keys - should we try to address that case?

- There is a tiny chance of failure during key generation (if F happens to be
  selected as all 0); this happens with probability < 2^-800 (that is, it'll
  never happen in practice, unless the random number generator broke).  When
  this happens, the computation of the inverse of F will fail; what happens
  in that case would depend on the inverter implementation.
  Should we ignore it or address it?

- It appears that the parameter set HPS4096821 was added lately to the NTRU
  definition, and did not undergo the same vetting that the other parameter
  sets did.  As such, it is unclear whether that parameter set gives the
  claimed level of security.  Should we remove it from this RFC, or just add
  some warning text within the security considerations?

## Test vectors

TBD

{backmatter}

# Acknowledgments

Acknowledge TBD.

<reference anchor='NTRU' target='https://ntru.org/f/ntru-20190330.pdf'>
    <front>
        <title>NTRU: Algorithm Specications And Supporting Documentation</title>
        <author initials='C' surname='Chen' fullname='Cong Chen'></author>
        <author initials='O.' surname='Danba' fullname='Oussama Danba'></author>
        <author initials='J.' surname='Hoffstein' fullname='Jeffrey Hoffstein'></author>
        <author initials='A.' surname='Hulsing' fullname='Andreas Hulsing'></author>
        <author initials='J.' surname='Rijneveld' fullname='Joost Rijneveld'></author>
        <author initials='J. M.' surname='Schanck' fullname='John M. Schanck'></author>
        <author initials='P.' surname='Schwabe' fullname='Peter Schwabe'></author>
        <author initials='W.' surname='Whyte' fullname='William Whyte'></author>
        <author initials='Z.' surname='Zhang' fullname='Zhenfei Zhang'></author>
        <date year='2019'/>
    </front>
</reference>
