# PIC-X

**Status: Experimental / Not production-ready — non-normative.**

Provenance Identity Continuity Exchange. Verifiable Authority Continuity across execution boundaries.

> **Attribution Notice**
> This work is based on the **Provenance Identity Continuity (PIC) Model**, a theoretical framework created by **Nicola Gallo**.
> This repository and all related materials are published and maintained by **Nitro Agility S.r.l.**
> This repository is **non-normative**: the [PIC Specification](https://github.com/pic-protocol/pic-spec) always takes precedence.

---

## What this repository is

This is the **experimental line of PIC-X**. It exists to explore designs, encodings, and implementation strategies
ahead of anything that could be considered stable. Everything here is provisional by construction.

⚠️ **This is not the production version of PIC-X.** Do **not** deploy it, depend on it, or treat any part of it as a
stable interface.

Concretely, this means:

- **No stability guarantees.** APIs, wire formats, artifact layouts, and repository structure can change at any time,
  without deprecation periods and without migration paths.
- **Not normative.** Where anything here disagrees with the [PIC Spec](https://github.com/pic-protocol/pic-spec), the
  spec wins. This repository never redefines PIC invariants.
- **Not audited.** No security review, no hardening, no operational readiness. Assume rough edges everywhere,
  including in anything touching keys, signatures, or verification.
- **No support commitment.** Issues and discussions are welcome, but there is no release cadence, no SLA, and no
  backwards-compatibility promise.

## What to use instead

| If you want…                    | Go to                                                              |
| ------------------------------- | ------------------------------------------------------------------ |
| The normative definition of PIC | [pic-spec](https://github.com/pic-protocol/pic-spec)               |
| Runnable reference prototypes   | [pic-prototyping](https://github.com/pic-protocol/pic-prototyping) |
| A production-ready PIC-X        | Not available yet — this repository is the experimental line       |

---

## License

See [LICENSE](LICENSE).
