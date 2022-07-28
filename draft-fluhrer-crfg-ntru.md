---
title: "NTRU Key Encapsulation"
category: info

docname: draft-fluhrer-crfg-ntru-latest
submissiontype: IETF  # also: "independent", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
#  group: WG
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

normative:

informative:


--- abstract

TODO Abstract


--- middle

# Introduction

NIST has run a competition to select postquantum primitives, for the key exchange mechanism, they selected Kyber.  Now, one issue with Kyber is that there are plausible patent claims against it; while NIST has agreements with the patent holders, they have not released those agreements, hence it is unknown whether those would be universally acceptable; if not, there will be organizations for which Kyber is unusable until the patents expire.
This draft documents NTRU, which is an alternative postquantum key exchange mechanism.  It is believed to be IPR free; this alternative would be usable by everyone.


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
