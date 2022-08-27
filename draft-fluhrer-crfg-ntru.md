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

# Cryptographic Dependencies

## Polynomials

NTRU is based on polynomials; these can be viewed as a vector of N small values (between 0 and Q-1), where the values of both N and Q are specified by the parameter set.  In all parameter sets, Q is less than 65536, hence each small value fits within a 16 bit value.

# NTRU Encryption

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
