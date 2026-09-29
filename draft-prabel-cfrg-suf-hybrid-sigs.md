---

###
title: "Hybrid Digital Signatures with Strong Unforgeability"
abbrev: "SUF Hybrid Signature"
category: std

docname: draft-prabel-cfrg-suf-hybrid-sigs-02
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
venue:
  group: Cryptography Forum
  type: Research Group
  mail: cfrg@ietf.org
  arch: https://mailarchive.ietf.org/arch/browse/cfrg/
  github: lucasprabel/draft-cfrg-suf-hybrid-sigs

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
 - name: John | Preuß Mattsson
   org: Ericsson AB
   email: john.mattsson@ericsson.com

informative:
 RFC6979:
 RFC8032:
 RFC9794:
 I-D.draft-ietf-lamps-pq-composite-sigs: LAMPS-COMPOSITE
 I-D.draft-ietf-pquip-hybrid-signature-spectrums: HYBRID-SPECTRUMS
 I-D.draft-devevey-cfrg-silithium: SILITHIUM
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
 BUFF:
   title: "BUFFing signature schemes beyond unforgeability and the case of post-quantum signatures"
   date: 2021
   author:
      - ins: C. Cremers
        name: Cas Cremers
      - ins: S. Düzlü
        name: Samed Düzlü
      - ins: R. Fiedler
        name: Rune Fiedler
      - ins: M. Fischlin
        name: Marc Fischlin
      - ins: C. Janson
        name: Christian Janson
   target: https://ieeexplore.ieee.org/document/9519420

--- abstract

This document proposes two PQ/T (Post-Quantum/Traditional) hybrid signature constructions that achieve strong unforgeability under chosen-message attacks (SUF-CMA). The first, a black-box construction, achieves SUF-CMA security provided that the second component (typically the post-quantum one) is SUF-CMA secure; it differs from the current composite hybrid approach by binding the second (post-quantum) signature to the concatenation of the message and the first (traditional) signature. This approach ensures that hybrid signatures maintain SUF-CMA security even when the first component only provides EUF-CMA security.

The second, a non-black-box construction, requires the first (traditional) component to be built from the Fiat-Shamir paradigm, and binds the post-quantum signature directly into that component's challenge computation rather than treating it as an opaque sign/verify oracle. This variant is SUF-CMA secure as long as at least one of the two components is SUF-CMA secure.

--- middle

# Introduction

With the emergence of post-quantum (PQ) digital signatures, several groups (including ETSI CYBER and IETF LAMPS, TLS JOSE, SSHM) have explored hybrid constructions combining traditional and PQ algorithms. The main goal is to ensure long-term security during the transition to post-quantum cryptography, acknowledging that traditional algorithms are more mature than post-quantum ones and that the latter still raise uncertainty about their security.

Current composite hybrid schemes typically provide existential unforgeability under chosen-message attacks (EUF-CMA), but do not ensure strong unforgeability. SUF-CMA extends EUF-CMA by requiring that it be computationally infeasible to produce a new valid signature even for a message-signature pair previously observed. This distinction has practical implications in preventing message replay, transaction duplication, and log poisoning.

Although several recent algorithms such as EdDSA, ML-DSA, and SLH-DSA claim to achieve SUF-CMA security, some popular traditional schemes (e.g. ECDSA) only achieve EUF-CMA. Therefore, constructing a hybrid digital signature scheme maintaining SUF-CMA when one component does not is of particular interest.

To address this concern, this document specifies two hybrid constructions that achieve SUF-CMA security. The first is a generic (black-box) construction that guarantees SUF-CMA security when the second underlying component (e.g. the PQ scheme) is SUF-CMA. It is quite simple, can be applied generically across PQ/T signature combinations, and was originally proposed in {{BH23}}, though its SUF-CMA is not analyzed in the article. It could also be used for a hybrid PQ/PQ security, relying on two post-quantum components. The second is a non-black-box construction, for a first component built from the Fiat-Shamir paradigm (e.g. EdDSA), which guarantees SUF-CMA security as long as at least one of the two components is SUF-CMA.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document follows the terminology for post-quantum hybrid schemes defined in {{RFC9794}}.

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

# Black-box Construction {#black-box}

The proposed construction ensures that the second (nesting) signature binds the first (nested) signature, making the overall scheme SUF-CMA as long as the (typically PQ) component is SUF-CMA secure. The hybrid signature construction is defined in the following subsections.

Before signing a message `m`, the hybrid scheme derives a message representative `m'` from `m` to address specific security concerns, and in particular to achieve non-separability, following a similar approach to {{-LAMPS-COMPOSITE}}.

## Hybrid Key Generation

~~~
Generate component keys

- Generate (pk1, sk1) for the traditional scheme.
- Generate (pk2, sk2) for the post-quantum scheme.
- The hybrid public key is `pk = (pk1 || pk2)`.
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
- `Label`: a label which is specific to the particular component algorithms being used.
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

The hybrid construction in {{-LAMPS-COMPOSITE}} only provides SUF-CMA security if both components are providing SUF-CMA security and one of them is deterministic. Indeed, requiring at least one deterministic component prevents a "mix-and-match" forgery and is therefore necessary to claim SUF-CMA security. In particular, as traditional signatures do not provide any security against quantum attackers, when {{-LAMPS-COMPOSITE}} is used for PQ/T hybrid scheme, it does not provide SUF-CMA security against quantum attackers. In this document, only the second component needs to be SUF-CMA so that the hybrid scheme achieves SUF-CMA security.

In contrast to {{-LAMPS-COMPOSITE}}, the signing process of the hybrid construction proposed in this document cannot be parallelized. Indeed, computing the hybrid signature `s = (s1 || s2)` requires to compute `s1 = Sign_1(sk1, m')` first in order to compute `s2 = Sign_2(sk2, m' || s1)`.

Another related construction is {{-SILITHIUM}}, which combines EC-Schnorr and ML-DSA. Although presented as a standalone scheme rather than a generic framework, its signing process follows a pattern similar to the non-black-box construction described in this document: the post-quantum (ML-DSA) signature is computed over a commitment produced during the traditional (EC-Schnorr) signing process, and the traditional challenge is then derived from that post-quantum signature. This binding mechanism illustrates a concrete instantiation of the non-black-box approach and achieves comparable strong unforgeability guarantees.

# Non-black-box Construction {#non-black-box}

The proposed construction of this section ensures that the overall scheme is SUF-CMA as long as at least one component is SUF-CMA secure. The hybrid signature construction is defined in the following subsections.

The hybrid can be used for signature schemes that are built from the Fiat-Shamir paradigm as the first component and from any signature scheme as the second component. Hence, they use a canonical identification scheme (ID) underlying a Fiat-Shamir construction and a signature scheme (Sig_2).
This applies to combining EdDSA and any post-quantum signature scheme, for example ML-DSA.

Before signing a message `m`, the hybrid scheme derives a message representative `m'` from `m` to address specific security concerns, and in particular to achieve non-separability, following a similar approach to {{-LAMPS-COMPOSITE}}.

## Hybrid Key Generation

~~~
Generate component keys

- Generate (pk1, sk1) for the (traditional) ID scheme.
- Generate (pk2, sk2) for the (post-quantum) signature scheme.
- The hybrid public key is `pk = (pk1, pk2)`.
~~~

## Hybrid Sign

The Hybrid.Sign algorithm consists of applying the Fiat-Shamir paradigm for the first signature component. During the process (after the commitment has been computed), the second component is applied by signing the message and the commitment. The remainder of the Fiat-Shamir signature is computed using the second signature component instead of the message and the commitment as usual.

We use the following notations:

- `com`: the commitment output by `ID.Com`.
- `st`: the internal state output by `ID.Com(sk1)` alongside `com`.
- `chl`: the challenge.
- `rsp`: the response of the identification scheme.

~~~
Generate the message representative

- Compute m' = Prefix || Label || len(ctx) || ctx || pk's || PH(m)

Generate hybrid signature

- Compute (com, st) = ID.Com(sk1)
- Compute m'' = PH(1 || m' || com)
- Compute s2 = Sig.Sign_2(sk2, m'')
- Compute chl = PH(2 || s2)
- Compute rsp = ID.Rsp(sk1, com, chl, st)
- Output the hybrid signature s = (rsp || s2)
~~~

In the computation of the message representative:

- `Prefix` is the byte encoding of the string "SUFHybridSignature2025", which in hexadecimal is "5355464879627269645369676E617475726532303235".
- `Label`: a label which is specific to the particular component algorithms being used.
- `len(ctx)`: a single byte representing the length of `ctx`.
- `ctx`: the context bytes.
- `pk's`: the concatenation of pk1 and pk2.
- `PH(m)`: the hash of the message to be signed.

## Hybrid Verify

~~~
Verify hybrid signature

- Compute m' = Prefix || Label || len(ctx) || ctx || pk's || PH(m)
- Parse s as (rsp || s2)
- Check that rsp is within bounds (for EdDSA: 0 <= S < L); otherwise, reject
- Compute chl = PH(2 || s2)
- Compute com = ID.ExtCom(pk1, chl, rsp)
- Compute m'' = PH(1 || m' || com)
- Compute Verify_2(pk2, m'', s2)
- Accept if verification succeeds.
~~~

## Security and Applicability {#nbb-security}
The hybrid is SUF-CMA if one of the underlying signatures is SUF-CMA secure. Additionally, the ID scheme must have unique responses and the second signature component (post-quantum component) must fulfill message-bound security (MBS) {{BUFF}} and random-message validity (RMV) {{Jan25}}.

The first requirement (on the traditional scheme) is fulfilled by EdDSA which is built from an ID scheme with unique responses. The second requirement (on the post-quantum scheme) is fulfilled by any of NIST standards/winners, i.e. ML-DSA, SLH-DSA, Falcon (to be FN-DSA).



# Why the Binding Hybrid is Required

Some deployments additionally require SUF-CMA, i.e. that no party other than the signer can produce a new valid signature, even for an already-signed message. This matters for example when signature values are themselves used as identifiers, deduplication keys, or inputs to other hashes (e.g. transaction identifiers, signed log entries). While a parallel hybrid is SUF-CMA only if both components are SUF-CMA and one is deterministic, it loses SUF-CMA in particular once a CRQC breaks the traditional component. Therefore, binding the components allows SUF-CMA to rely on a single component.

For the black-box construction, any successful forgery falls into one of two categories:

* New signature on a new input:  
  The attacker produces a hybrid signature on an input `m' || s1*` that the legitimate signer never signed with the second component. The attacker would then need to forge a valid `s2*` over this new input. Producing such an `s2*` is a forgery against the PQC algorithm.

* Different second-signature on an already-signed input:  
  The attacker reuses an existing `(m', s1)` but fabricates a distinct `s2*` for the same `(m' || s1)`, yielding two valid second signatures for one message.

Both outcomes constitute a SUF-CMA forgery against the second component: the first case for a new message, the second for a second valid signature on an existing message.  If the second component is SUF-CMA secure, neither case is computationally feasible, and the combined hybrid inherits SUF-CMA security.

For the non-black-box construction, the binding works in both directions: the second signature `s2` is computed over the commitment `com` (and hence over the message), and the challenge `chl`, and thus the response `rsp`, is derived from `s2`. Neither component can therefore be modified independently of the other.

## ECDSA vs EdDSA in Hybrid Constructions

Neither ECDSA (secp256r1/secp384r1) nor EdDSA (Ed25519/Ed448) are quantum-safe. However, they differ against classical adversaries:

* ECDSA is not SUF-CMA, even classically and even with deterministic nonces {{RFC6979}}: given a valid signature `(r, s)`, anyone can compute `(r, n - s)`, and this is also a valid signature on the same message.

* EdDSA is SUF-CMA against classical adversaries, provided that verification enforces the checks of {{RFC8032}}, in particular `0 <= S < L`. Its signing is deterministic, but this is a property of the signing algorithm only, and the verifier cannot check it. Moreover, anyone holding the private key can produce many distinct valid signatures on the same message. Once a CRQC recovers an EdDSA private key, EdDSA therefore loses SUF-CMA, just like ECDSA.

This has the following consequences for hybrid constructions:

* A parallel hybrid with an ECDSA component is never SUF-CMA. A parallel hybrid with an EdDSA component can be SUF-CMA against classical adversaries, but not against a quantum adversary.

* The black-box construction of this document achieves SUF-CMA with either ECDSA or EdDSA as the first component, as long as the PQ component is SUF-CMA.

* The non-black-box construction applies to EdDSA, which is built from an identification scheme with unique responses, but not to ECDSA, which does not follow the Fiat-Shamir paradigm. The hybrid verification MUST enforce `0 <= S < L` on the response. Otherwise, replacing `S` with `S + L` yields the same commitment and the same `s2`, so anyone can derive a second valid hybrid signature on the same message, and the construction is not SUF-CMA.

# Security Considerations

## Security Model and Motivation

Both constructions are EUF-CMA as long as at least one component is EUF-CMA secure (for the non-black-box construction, under the additional requirements of {{nbb-security}}). This document additionally targets SUF-CMA, which constructions such as {{-LAMPS-COMPOSITE}} do not guarantee in general.

The black-box construction ({{black-box}}) aims to guarantee strong unforgeability of the hybrid signature whenever the second component is SUF-CMA secure. This is in contrast to {{-LAMPS-COMPOSITE}}, where SUF-CMA of the composite generally requires both components to be SUF-CMA. The non-black-box construction ({{non-black-box}}) strengthens this further: because the Fiat-Shamir response is bound to the second signature with `chl = PH(2 || s2)`, SUF-CMA of the overall construction holds if either component is SUF-CMA secure, provided that the ID scheme has unique responses (enforced by verification) and ths second signature scheme is MBS and RMV.

## SUF-CMA Security

### Why SUF-CMA matters

While EUF-CMA security could be sufficient in several use cases, weaknesses in EUF-only schemes allow signature malleability (producing a new valid signature on an already-signed message without the private key), enabling real-world exploits such as replay of messages, double receipts, and log poisoning. Moreover, many current deployed systems implicitly assume that all digital signatures are SUF-secure, and that a single unique signature exists per message.

For this reason, the construction ensures that if the second component is SUF-CMA, the hybrid resists such attacks, like recent standardized signature schemes (EdDSA, ML-DSA, SLH-DSA, etc.).

### Security Rationale

For the black-box construction, an adversary attempting to forge `(m*, s1*, s2*)` must either:

- Produce `s2*` on an input `m'* || s1*` that was never signed by the second component (because the message or `s1*` is new), which is infeasible if the second scheme is EUF-CMA;

or

- Reuse an existing `(m', s1)` pair with a different `s2*`, which is infeasible if the second scheme is SUF-CMA.

Consequently, if the second component is SUF-CMA, the black-box construction is SUF-CMA regardless of the security of the first component, including when the latter only provides EUF-CMA security or is fully broken by a CRQC.

In contrast, if the second scheme is not SUF-CMA, the second attack is no longer excluded, and the construction is not SUF-CMA in general.

For the non-black-box construction, the same reasoning applies to `s2`. In addition, reusing an existing `s2` with a different response `rsp*` is excluded, because `s2` determines the challenge, and the ID scheme has unique responses (enforced by verification). The construction is therefore SUF-CMA as long as the PQ component is SUF-CMA. It is also SUF-CMA if the traditional component is SUF-CMA, under the requirements of {{nbb-security}}.

This contrasts with classical composite hybrids (e.g. `trad(M) || PQ(M)`) where the PQ signature does not authenticate the output of the traditional signature, leaving possible avenues for replay or signature substitution.

## Non-Separability

The document {{-HYBRID-SPECTRUMS}} defines both notions of Weak Non-Separability (WNS) and Strong Non-Separability (SNS).

The black-box hybrid construction in this document achieves WNS because the `Prefix` of the message representative `m'` is evidence that a verifier may be able to identify, preventing the validation of a component signature which would have been removed from the hybrid signature.

However, SNS is not achieved, as `s1` stripped from a hybrid signature `s = (s1 || s2)` is a valid component signature of the message `m'` and `s2` is a valid component signature of the message `m' || s1`.

For the non-black-box construction, the two components behave differently. The PQ signature `s2` can be stripped from the hybrid signature and is a valid component signature on `m'' = PH(1 || m' || com)`, so SNS is not achieved for the PQ component. However, presenting `s2` as a signature on a chosen message would require inverting `PH`. Conversely, the traditional component cannot be separated: `rsp` alone is not an EdDSA signature, and turning `(com, rsp)` into a valid EdDSA signature on some message `M` would require the EdDSA challenge `H(com || pk1 || M)` to match `chl = PH(2 || s2)`, which is infeasible for a secure hash function. Informally, the non-black-box construction therefore achieves SNS for the traditional component, but not for the PQ component.


# IANA Considerations

This document has no IANA actions.

--- back

# Comparison of Security Properties

This appendix compares the security properties of the two constructions of this document with those of {{-SILITHIUM}}:

- Black-box construction ({{black-box}}): `s1 = Sign_1(sk1, m')` and `s2 = Sign_2(sk2, m' || s1)`.
- Non-black-box construction ({{non-black-box}}): the traditional component follows the Fiat-Shamir paradigm (e.g. EdDSA), `rsp = ID.Rsp(sk1, com, chl, st)` and `s2 = Sig.Sign_2(sk2, m'')`.
- Silithium: EC-Schnorr combined with ML-DSA, with ML-DSA signing the message with the context string `R || P`, and the EC-Schnorr challenge `c` extracted from the ML-DSA signature.

In the table below, "T" refers to the traditional component and "PQ" to the post-quantum component. A cell "PQ" (resp. "T") means that the property holds if the PQ (resp. traditional) component provides it. "PQ or T" means that the property holds as long as at least one component provides it. "PQ and T" means that both components must provide it. Against a quantum adversary, the traditional component provides no security, so a cell "PQ or T" reduces to "PQ". When a security property relies on several properties of a component, these properties are given in parentheses.

## Summary

| Property | Black-box | Non-black-box | Silithium |
|---|---|---|---|
| Specification | {{black-box}} | {{non-black-box}} | {{-SILITHIUM}} |
| EUF-CMA | PQ or T | PQ or T | PQ or T |
| SUF-CMA | PQ | PQ or T | PQ |
| Non-separability of the T component | WNS | SNS | SNS |
| Non-separability of the PQ component | WNS | None | WNS |
| Exclusive Ownership (EO) | PQ and T (EO) | PQ (EO and MBS) | PQ (EO and MBS) |
| Message-Bound Security (MBS) | PQ or T | PQ | PQ |
| Traditional component | Any | Fiat-Shamir with unique responses (e.g. EdDSA) | EC-Schnorr |
| Components used as black boxes | T and PQ | PQ | PQ |
| Signature size | size(s1) + size(s2) | size(rsp) + size(s2) | size(x) + size(ML-DSA signature) |

## Existential Unforgeability (EUF-CMA)

Each construction is EUF-CMA as long as at least one component is EUF-CMA.

If the PQ component is EUF-CMA: in all three constructions, the PQ signature of a forgery on a new message is computed over an input that depends on this message (`m' || s1` for the black-box construction, `m''` for the non-black-box construction, and the message itself for Silithium). This input was never signed, so the PQ hybrid signature is a forgery against the PQ component.

If the traditional component is EUF-CMA: in the black-box construction, `s1` is a traditional signature on `m'`, which was never signed, so `s1` is a forgery against the traditional component. In the non-black-box construction and Silithium, the traditional component is a response to a challenge derived from the PQ signature, which is bound to the message and the commitment. This challenge plays the same role as in a regular Fiat-Shamir signature, so the traditional part is a forgery against the traditional component.

## Strong Unforgeability (SUF-CMA)

If the PQ component is SUF-CMA: in all three constructions, a new hybrid signature on a message either contains a new PQ signature, or reuses an existing one on the same input. In the first case, it is a forgery against the PQ component. In the second case, nothing else can change. In the black-box construction, the PQ signed input `m' || s1` fixes `s1`. In the non-black-box construction and Silithium, the PQ signature fixes the challenge, and the PQ input fixes the commitment. The response is then unique, provided that verification enforces the range check (0 <= S < L for EdDSA, 0 <= x < q for Silithium). All three constructions are therefore SUF-CMA whenever the PQ component is.

If the traditional component is SUF-CMA: only the non-black-box construction remains SUF-CMA. A new signature either has a new PQ input `m''`, a new `s2` on an existing input, or the same `s2` with a different response. In the first two cases, the adversary must produce a valid response to a new challenge, which is a forgery against the traditional component. The last case is impossible, since the response is unique for a given commitment and challenge. In the black-box construction, a new `s2` on an existing input directly gives a new hybrid signature, since nothing depends on `s2`. In Silithium, a new ML-DSA signature on the same message and context that keeps the same challenge `c` can be combined with the existing `x`.

## Non-Separability

In the black-box construction, both components are separable: `s1` is a valid signature on `m'`, and `s2` is a valid signature on `m' || s1`. Since both signed inputs begin with `Prefix`, the construction provides WNS, but not SNS, for both components.

In the non-black-box construction, the traditional component provides SNS: `rsp` alone is not an EdDSA signature, and using `(com, rsp)` as an EdDSA signature on some message would require the EdDSA challenge to match `chl`, which requires breaking the preimage resistance of the underlying hash. However, the PQ signature `s2` is separable, as a valid signature on the hash value `m''`.

Silithium behaves similarly for the traditional component, which provides SNS, since `c` is taken from the ML-DSA signature. The ML-DSA signature is separable, but because the context contains the EC-Schnorr public key `P`, a verifier may be able to identify it, which provides WNS for the PQ component.

## Exclusive Ownership (EO)

*Definition:* an adversary cannot produce a signature that is valid under two different public keys, possibly for different messages {{BUFF}}.

In the black-box construction, `m'` does not include the public keys. Therefore, an adversary can keep `pk2` and replace `pk1` with a key `pk1*` under which `s1` also verifies on `m'`. Since the input `m' || s1` and the key `pk2` are unchanged, `s2` still verifies. EO therefore requires the traditional component to provide EO. Symmetrically, replacing `pk2` requires the PQ component to provide EO.

In the non-black-box construction, `m'` includes `pk1 || pk2`. If a hybrid signature is valid under two public keys with different PQ keys, `s2` is valid under two different PQ keys, which breaks EO of the PQ component. If only the traditional keys differ, `m'`, and hence `m''`, differ, so `s2` is valid for two different inputs under the same PQ key, which breaks MBS of the PQ component. EO therefore relies on the EO and MBS of the PQ component.

In Silithium, the same reasoning applies. If the ML-DSA public keys differ, the ML-DSA signature is valid under two different keys, which breaks EO of ML-DSA. If only the EC-Schnorr public keys `P` and `P*` differ, the contexts `R || P` and `R* || P*` differ, so the ML-DSA signature is valid for two different contexts under the same key, which breaks MBS of ML-DSA. EO therefore relies on the EO and MBS of the PQ component.

## Message-Bound Security (MBS)

*Definition:* an adversary cannot produce a signature that is valid for two different messages under the same public key {{BUFF}}.

In the black-box construction, `m'` is part of the input of both components. A hybrid signature valid for two messages would give an `s1` valid for two different inputs `m'_1` and `m'_2`, and an `s2` valid for two different inputs `m'_1 || s1` and `m'_2 || s1`. The first breaks MBS of the traditional component, and the second breaks MBS of the PQ component. MBS therefore holds if either component provides it, assuming `PH` is collision-resistant.

In the non-black-box construction, a hybrid signature `(rsp, s2)` valid for two messages gives the same challenge `chl` and the same commitment `com` for both messages, but two different inputs `m''_1` and `m''_2`. Thus `s2` is valid for two different inputs, which breaks MBS of the PQ component. MBS therefore relies on the PQ component {{Jan25}}. The traditional component does not help here: its transcript `(com, chl, rsp)` is the same for both messages, since the message only enters the construction through `s2`.

In Silithium, a signature valid for two messages gives the same challenge `c`, the same response `x`, and hence the same nonce `R` and context `R || P` for both messages. The ML-DSA signature is then valid for two different messages with the same context, which breaks MBS of ML-DSA. MBS therefore relies on the PQ component. The traditional component does not help here: `R`, `c` and `x` are the same for both messages, since the message only enters the construction through the ML-DSA signature.
