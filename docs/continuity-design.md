# PIC-X continuity: current guarantees and future design

This document separates what PIC-X implements today from properties that require a future trusted
Execution Context. It is intentionally narrower than the mathematical PIC model: an implementation
claim is made only where the current service has evidence for it.

## Current mode: `artifact-linked`

PIC-X Profile 0.2 validates and advances a signed chain of artifacts. Discovery advertises this as
`pic_continuity.continuity_evidence_levels_supported = ["artifact-linked"]`.

At settlement, PIC-X verifies:

1. the predecessor checkpoint was signed by the realm and has not reached its absolute expiry;
2. the candidate token, Continuity COSE and Transition COSE are structurally consistent;
3. the issuer-signed SD-JWT is from a configured attester and binds the candidate signing key;
4. the disclosed executor-profile claims satisfy every constraint in the predecessor execution
   contract;
5. authority only attenuates, while execution-contract constraints only accumulate; and
6. the resulting checkpoint is signed by the realm and synchronously audited before release.

Profile 0.2 calls the SD-JWT container `proof_of_relationship`. PIC-X retains that wire name for
compatibility. Its current contents are more precisely **executor-profile and key evidence**. They
do not show that a trusted boundary observed a concrete handoff from one execution occurrence to
another. Therefore PIC-X does not currently claim the full semantic predicate
`PoR(s_i, s_{i+1})`; it establishes only the artifact-linked part needed to validate a candidate.

## Capability matrix

| Property | Current status | What PIC-X has today | Future work / owner |
| --- | --- | --- | --- |
| Signed artifact lineage | Implemented | Realm-signed predecessor, workload-signed candidate artifacts, preserved lineage identifier and position | Maintain and test |
| Authority attenuation | Implemented | Removed identity/invariant entries cannot be reintroduced by settlement | Maintain and test |
| Execution-contract refinement | Implemented | Additive, conjunctive constraints; the successor must satisfy the predecessor contract | Maintain and test |
| Executor profile and key possession | Implemented | Trusted-issuer SD-JWT disclosures and `cnf.jwk`; candidate signatures must match the bound key | Maintain; add per-claim issuer policy |
| Unknown successor / fan-out | Implemented intentionally | Multiple independently keyed successors may advance the same checkpoint | Preserve; do not add global predecessor consumption |
| Semantic `PoR(s_i, s_{i+1})` | Partial | Artifact and profile relationships are verified; no trusted observation of the handoff occurrence exists | Execution Context supplies observed-handoff evidence |
| Request binding | Not implemented | Settlement has no request or transport occurrence to compare with the candidate | Execution Context commits to the consumed request/occurrence |
| Transport/channel continuity | Not implemented | PIC-X does not receive a trusted channel identity | Execution Context supplies authenticated channel evidence where applicable |
| Complete mediation | Not implemented by PIC-X | PIC-X can settle artifacts but cannot prove every protected action passed through settlement | Resource boundary/Execution Context must enforce mediation |
| Causal attribution | Not implemented | A valid candidate proves control of a key, not that a particular predecessor caused a particular runtime action | Boundary-issued occurrence receipt or equivalent observation |
| Anti-replay / single consumption | Intentionally deferred | A predecessor remains reusable, which is required for worker pools and fan-out | If needed, scope replay protection to occurrence identifiers, not the predecessor globally |
| Revocation | Intentionally deferred | Absolute expiry and signing-key retention bound acceptance; there is no per-lineage early revocation | Add a separately specified revocation mechanism |
| Per-claim attester trust | Not implemented | Configuring an issuer currently trusts it for all disclosed claims used by contracts | Add claim/schema allow-lists to attester policy |
| Binary relational predicates or disjunction | Not implemented | Current execution contracts are unary and conjunctive | Extend only with an explicit protocol and policy design |

## Why the successor is not pre-bound

A publisher may write to Kafka or another queue without knowing whether zero, one or many workers
will consume the message. The successor key may not exist yet. PIC-X therefore must not require the
publisher to name or encrypt to a successor at publication time.

```text
publisher occurrence
        |
        | signed checkpoint/candidate material
        v
   queue or broker
      /       \
worker A    worker B       successor identities and keys become known here
```

Each worker presents its own executor-profile credential and signs its own candidate. Sibling
advancements from the same checkpoint are valid branches. A global "checkpoint already consumed"
bit would destroy this property and is not the intended anti-replay design.

## Future trusted Execution Context

The smallest coherent next step is a trusted handoff observer at the consumption boundary. In the
PIC deployment this should be the Execution Context, not PIC-X guessing from transport metadata.
The observer can issue a signed receipt or equivalent commitment after it sees the concrete
consumption event. Such evidence can bind:

- the predecessor/candidate artifact digest;
- a fresh occurrence identifier;
- the consuming executor profile or locally authenticated principal;
- the relevant request/message digest; and
- channel facts, only when the deployment can authenticate them.

The receipt is produced when a consumer is selected, so it works with unknown successors and
fan-out. It need not require a successor public key to exist at publication time. PIC-X can then
validate that receipt and justify `evidence => PoR` for the observed occurrence.

This does require new trusted infrastructure: the Execution Context must observe the handoff,
protect a signing key or equivalent attestation mechanism, and expose verifiable evidence. Until
that boundary exists, adding another self-signed field to the current candidate would not close the
semantic gap.

## Concrete future work

### Phase 1 — evidence contract

- Define the Execution Context receipt schema and its exact trust assumptions.
- Define occurrence identifiers so replay protection is per observed delivery/attempt and does not
  prohibit legitimate sibling branches.
- Define request/message binding independently of transport binding.
- Specify how a consumer with no pre-existing key is authenticated locally and how its profile is
  represented in the receipt.
- Define which party issues, verifies and retains each piece of evidence.

### Phase 2 — protocol integration

- Add a new evidence type/version instead of changing the meaning of Profile 0.2 SD-JWT evidence.
- Extend discovery so clients can distinguish `artifact-linked` from observed-handoff evidence.
- Implement receipt verification and make request binding fail closed when the stronger mode is
  selected.
- Preserve fan-out explicitly in conformance tests.

### Phase 3 — enforcement properties

- Integrate the Execution Context at protected resource boundaries for complete mediation.
- Connect accepted occurrence evidence to audit events for causal attribution.
- Add optional occurrence-scoped replay registers.
- Add revocation as an independent mechanism with explicit state and availability semantics.

### Independent hardening

- Scope trusted attesters by allowed claims/schema instead of issuer-wide trust.
- Align workspace dependency versions, release tags and published crates during the release process.
- Keep compatibility tests for the legacy `proof_of_relationship` field until a versioned protocol
  replaces it.

## Safe claim language

For the current implementation, say:

> PIC-X excludes authority mixing by construction within a validated artifact lineage and enforces
> executor-profile conformance at each settled advancement.

Do not currently say that PIC-X proves an observed causal handoff, binds the transport request, or
provides complete mediation. Those become supportable only when the trusted Execution Context and
its evidence contract are implemented and selected.
