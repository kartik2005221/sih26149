# Signing keys — policy

## The rule (Production)

**In production, real private signing keys never live in this repository and are never shipped inside any application bundle or client system.**
A wiping tool whose private key ships in production with its app is a forgery kit: anyone could mint "certified wiped" certificates. That failure mode would invalidate every certificate an authority has ever issued, so it is treated as unacceptable rather than unlikely.

`.gitignore` blocks `*private*.pem` / `*private*.key` repo-wide as a mechanical backstop (with an exception only for the demo key below).

## Real deployment

- Key generation runs **once, out-of-band**, on the issuing authority's own machine
  (an accredited forensic authority).
- The private key stays on that machine, offline where possible, backed up under the
  organization's key-management policy. Losing it means re-keying; leaking it means
  distrusting every prior certificate.
- The **public key** is what gets distributed: pinned in the verification portal
  (`verification-portal/keys.json`) and shipped read-only with verifiers (`s0 verify`).
- Rotation: publish the new public key alongside the old during a transition window;
  certificates record `public_key_fingerprint`, so old certs stay verifiable against the
  old pinned key.

## In this repository (prototype & demonstration)

- `demo_issuer_public.pem` — Demonstration issuer public key, pinned in verifiers (`verification-portal/keys.json`, `s0 verify`). Clearly labelled DEMO.
- `demo_issuer_private.pem` — Demonstration private key shipped intentionally in this prototype repository for out-of-the-box demo and evaluation use. Production deployments generate their private keys out-of-band using `s0 keygen` and never commit or distribute them.

## What this does NOT protect against

Certificate signing proves *who issued a claim*, not that the claim is true. A signed
certificate from an operator who pointed the tool at the wrong disk is a perfectly signed lie.
Chain-of-custody around the operator remains a human process; the certificate makes it
auditable, not foolproof.

