---

###
title: "Hybrid Digital Signatures with Strong Unforgeability"
abbrev: "SUF Hybrid Signature"
category: std

docname: draft-prabel-suf-hybrid-sigs
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: Security
workgroup: CFRG
keyword:
 - CFRG
 - Migration
 - PQC

author:
 -  ins: L. Prabel
    fullname: Lucas Prabel
    organization: Huawei
    email: lucas.prabel@huawei.com
 -  ins: G. Wang
    fullname: Guilin Wang
    organization: Huawei
    email: wang.guilin@huawei.com
 -  ins: J. Janneck
    fullname: Jonas Janneck
    organization: Ruhr University Bochum
    email: jonas.janneck@rub.de
 -  ins: T. Reddy
    fullname: Tirumaleswar Reddy
    organization: Nokia
    city: Bangalore
    region: Karnataka
    country: India
    email: "kondtir@gmail.com"

informative:
 I-D.draft-ietf-pquip-pqt-hybrid-terminology: HYBRID-TERMINOLOGY
 I-D.draft-ietf-lamps-pq-composite-sigs: LAMPS-COMPOSITE
 I-D.draft-ietf-pquip-hybrid-signature-spectrums: HYBRID-SPECTRUMS
 BH23:
   title: "A Note on Hybrid Signature Schemes"
   date: July 2023
   author:
      - ins: N. Bindel
        name: Nina Bindel
      - ins: B. Hale
        name: Britta Hale
   target: https://eprint.iacr.org/2023/423.pdf
 Jan25:
   title: "Bird of Prey: Practical Signature Combiners Preserving Strong Unforgeability"
   date: October 2025
   author:
      - ins: J. Janneck
        name: Jonas Janneck
   target: https://eprint.iacr.org/2025/1844.pdf

--- abstract

This document proposes a generic hybrid signature construction that achieves strong unforgeability under chosen-message attacks (SUF-CMA), provided that the second component (typically the post-quantum one) is SUF-CMA secure. The proposed hybrid construction differs from the current composite hybrid approach by binding the second (post-quantum) signature to the concatenation of the message and the first (traditional) signature. This approach ensures that hybrid signatures maintain SUF-CMA security even when the first component only provides EUF-CMA security.

--- middle

# Introduction

With the emergence of post-quantum (PQ) digital signatures, several working groups (including LAMPS, TLS and JOSE) have explored hybrid constructions combining traditional and PQ algorithms. The main goal is to ensure long-term security during the transition to post-quantum cryptography, acknowledging that traditional algorithms are more mature than post-quantum ones and that the latter still raise uncertainty about their security.

Current composite hybrid schemes typically provide existential unforgeability under chosen-message attacks (EUF-CMA), but do not ensure strong unforgeability. SUF-CMA extends EUF-CMA by requiring that it be computationally infeasible to produce a new valid signature even for a message-signature pair previously observed. This distinction has practical implications in preventing message replay, transaction duplication, and log poisoning.

Although several recent algorithms such as EdDSA, ML-DSA, and SLH-DSA claim to achieve SUF-CMA security, some popular traditional schemes (RSA, ECDSA) only achieve EUF-CMA. Therefore, constructing a hybrid digital signature scheme maintaining SUF-CMA when one component does not is of particular interest.

To addresses this concern, this document specifies a generic hybrid construction that guarantees SUF-CMA security when the second underlying component (e.g. the PQ scheme) is SUF-CMA. The construction is quite simple and can be applied generically across PQ/T signature combinations. It is originally proposed in {{BH23}}, though its SUF-CMA is not analyzed in the article.The construction could also be used for a hybrid PQ/PQ security, relying on two post-quantum components.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document follows the terminology for post-quantum hybrid schemes defined in {{-HYBRID-TERMINOLOGY}}.

This section recalls some of this terminology, but also adds other definitions used throughout the whole document:

*EUF-CMA*:  Existential Unforgeability under Chosen Message Attack.

*SUF-CMA*:  Strong Unforgeability under Chosen Message Attack.

*Post-Quantum Asymmetric Cryptographic Algorithm*:  An asymmetric
cryptographic algorithm that is intended to be secure against
attacks using quantum computers as well as classical computers.
They can also be called quantum-resistant or quantum-safe algorithms.

*PQ/T Hybrid Digital Signature*:  A multi-algorithm digital signature scheme made up of two or more component digital signature algorithms where at least one is a post-quantum algorithm and at least one is a traditional algorithm.

*Post-Quantum Traditional (PQ/T) Hybrid Composite Scheme*:  A multi-algorithm scheme where at least one component algorithm is a post-quantum algorithm and at least one is a traditional algorithm and the resulting composite scheme is exposed as a singular interface of the same type as the component algorithms.

*Component Scheme:*  Each cryptographic scheme that makes up a PQ/T hybrid scheme or PQ/T hybrid protocol.

# Proposed Construction

The proposed construction ensures that the second (nested) signature binds the first (nested) signature, making the overall scheme SUF-CMA as long as the (typically PQ) component is SUF-CMA secure. The hybrid signature construction is defined in the following subsections.

Before signing a message `m`, the hybrid scheme derives a message representative `m'` from `m` to address specific security concerns, and in particular to achieve non-separability, following a similar approach to {{-LAMPS-COMPOSITE}}.

## Hybrid Key Generation

~~~
Generate component keys

- Generate `(pk1, sk1)` for the traditional scheme.
- Generate `(pk2, sk2)` for the post-quantum scheme.
- The hybrid public key is `pk = (pk1, pk2)`.
~~~

## Hybrid Sign

The Hybrid.Sign algorithm consists in signing a message `m'` derived from `m` with the first component, and then signing the concatenation `m' || s1` of the derived message with the first signature with the second component.

~~~
Generate the message representative

- Compute m' = Prefix || Label || len(ctx) || ctx || PH(m)

Generate hybrid signature

- Compute s1 = Sign_1(sk1, m')
- Compute s2 = Sign_2(sk2, m' || s1)
- Output the hybrid signature s = (s1 || s2)
~~~

In the computation of the message representative:
- `Prefix` is the byte encoding of the string "SUFHybridSignature2025", which in hexadecimal is "5355464879627269645369676E617475726532303235".
- `Label`: a specific label which is specific to the particular component algorithms being used.
- `len(ctx)`: a single byte representing the length of `ctx`.
- `ctx`: the context bytes.
- `PH(m)`: the hash of the message to be signed.

## Hybrid Verify

~~~
Verify hybrid signature

- Compute m' = Prefix || Label || len(ctx) || ctx || PH(m)
- Parse s as (s1, s2)
- Compute Verify_1(pk1, m', s1)
- Compute Verify_2(pk2, m' || s1, s2)
- Accept if both verifications succeed.
~~~

## Related works

The hybrid construction in {{-LAMPS-COMPOSITE}} needs to have both components providing SUF-CMA security in order for the composite scheme to be SUF-CMA secure. In this document, only the second component needs to be SUF-CMA so that the hybrid scheme achieves SUF-CMA security.

In contrast to {{-LAMPS-COMPOSITE}}, the signing process of the hybrid construction proposed in this document cannot be parallelized. Indeed, computing the hybrid signature `s = (s1 || s2)` requires to compute `s1 = Sign_1(sk1, m')` first in order to compute `s2 = Sign_2(sk2, m' || s1)`.

In {{Jan25}}, three signature combiners are introduced. These combiners preserve strong unforgeability as long as at least one of the underlying schemes is strongly unforgeable. Several concrete instantiations with compact signature size are provided.

# Why the Binding Hybrid is Required

Hybrid constructions will have to provide SUF-CMA at the artifact level to ensure single-signature semantics and non-repudiation.  In many real-world deployments the artifact signing use case is central: software releases, firmware images, signed logs, and legal/financial documents are all artifacts that rely on a single, unambiguous signature to prove provenance and integrity. A hybrid design achieves SUF-CMA only if one signature component is cryptographically bound to the other, forming a binding hybrid rather than signing the same message independently.

Any successful forgery of a binding hybrid must fall into one of two categories:

* New second signature on a new input:  
  The attacker generates a new traditional signature `s1*` that the legitimate signer never produced. The attacker would then need to forge a valid `s2*` over the concatenation `m' || s1*`.  Producing such an `s2*` is a forgery against the PQC algorithm.

* Different second-signature on an already-signed input:  
  The attacker reuses an existing `(m', s1)` but fabricates a distinct `s2*` for the same `(m' || s1)`, yielding two valid second signatures for one message.

Both outcomes constitute a SUF-CMA forgery against the second component: the first case for a new message, the second for a second valid signature on an existing message.  If the second component is SUF-CMA secure, neither case is computationally feasible, and the combined hybrid inherits SUF-CMA security.

## Loss of Non-Repudiation in Parallel Hybrids under CRQC

As described in {{-LAMPS-COMPOSITE}}, composite hybrids produce multiple component signatures independently over the same message.  
Once a CRQC can forge the traditional component, an attacker can create an alternate classical signature `s1*` for a message that already has a valid hybrid signature `(s1, s2)`.  Because the PQC signature `s2` remains valid independently of the classical signature, the modified pair `(s1*, s2)` also verifies successfully.

While authenticity of the PQC component remains intact, non-repudiation cannot be guaranteed: multiple distinct hybrid signatures `(s1, s2)` and `(s1*, s2)` can exist for the same message. Therefore, once the classical algorithm becomes breakable, parallel hybrids no longer provide single-signature semantics, the assurance that each message corresponds to exactly one, unique signature from the signer.

On the contrary, this document’s hybrid construction, by binding the second signature `s2` to the first signature `s1`, ensures single-signature semantics and preserves non-repudiation.

## ECDSA vs EdDSA in Hybrid Constructions

Even though both ECDSA (secp256r1/secp384r1) and EdDSA (Ed25519/Ed448) become mathematically breakable once a CRQC can derive private keys from public keys, their behaviour in hybrid constructions differs significantly:

* ECDSA is randomized and non-deterministic, producing multiple distinct valid signatures for the same message. After CRQCs arrive, an attacker can generate arbitrarily many valid classical signatures, and hence multiple valid hybrids, destroying non-repudiation.

* Ed25519 and Ed448, in contrast, are deterministic and provide SUF-CMA security in their standard formulations, yielding a unique valid signature per message for a given key. This determinism eliminates malleability and preserves non-repudiation even if a CRQC later compromises the private key. In parallel hybrids, this property avoids ambiguity about which signature is authentic. In binding hybrids, EdDSA’s fixed, deterministic format enables unambiguous inclusion of `s1` in the PQC input (`m' || s1`), simplifying verification and ensuring consistent interpretation across implementations.

Consequently, ECDSA can only be used in a binding hybrid to preserve non-repudiation, and cannot be used in a parallel hybrid, because it is not SUF-CMA and becomes forgeable and repudiable once a CRQC can recover its private key.

# Security Considerations

## Security Model and Motivation

The hybrid construction described in this document aims to guarantee strong unforgeability of the composite signature whenever the second component is SUF-CMA secure. This is in contrast to the composite construction in {{-LAMPS-COMPOSITE}}, where SUF-CMA of the composite generally requires both components to be SUF-CMA. The design proposed here strengthens that property: SUF-CMA of the overall construction depends only on the SUF-CMA of the second component, regardless of the security level of the first one.

## SUF-CMA Security

### Why SUF-CMA matters

While EUF-CMA security could be sufficient in several use cases, weaknesses in EUF-only schemes allow "re-signing" the same message, enabling real-world exploits such as replay of messages, double receipts, and log poisoning. Moreover, many current deployed systems implicitly assume that all digital signatures are SUF-secure, and that a single unique signature exists per message.

For this reason, the construction ensures that if the second component is SUF-CMA, the hybrid automatically resists replay and duplication attacks, aligning with best practices in recent signature standards (EdDSA, ML-DSA, SLH-DSA, etc.).

### Security Rationale

Intuitively, an adversary attempting to forge `(m*, s1*, s2*)` must either:

- Forge `s2*` on `(m* || s1*)`, which is infeasible if the second scheme is SUF-CMA;

or

- Reuse an existing `(m, s1)` pair with a modified `s2`, which again breaks SUF-CMA of the second scheme.

Consequently, if the second component if SUF-CMA secure, the hybrid construction remains SUF-CMA secure even when the first component provides only EUF-CMA security.

In contrast, if the second scheme were only EUF-CMA, the second attack (re-signing the same message differently) would no longer be excluded, and the hybrid construction would not be SUF-CMA secure.

This contrasts with classical composite hybrids (e.g. `trad(M) || PQ(M)`)
where the PQ signature does not authenticate the output of the
traditional signature, leaving possible avenues for replay or
signature substitution.

## Non-Separability

The document {{-HYBRID-SPECTRUMS}} defines both notions of Weak Non-Separability (WNS) and Strong Non-Separability (SNS).

The hybrid construction in this document achieves WNS because the `Prefix` of the message representative `m'` is an evidence that a verifier may be able to identify, preventing the validation of a component signature which would have been removed from the composite signature.

However, SNS is not achieved, as `s1` stripped from a composite signature `s = (s1 || s2)` is a valid component signature of the message `m'` and `s2 ` is a valid component signature of the message `m' || s1`.

# IANA Considerations

This document has no IANA actions.
