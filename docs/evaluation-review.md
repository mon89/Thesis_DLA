# DLA Evaluation Review — Adversarial Testing Note

> Working note for revising §5 (Evaluation) of the DLA paper. It (1) explains
> why the current detection evaluation reads as a functional-conformance check
> rather than a security study, and (2) proposes a concrete adversarial test
> matrix that probes the cryptographic bindings DLA actually relies on. Line
> references point at the current repo.

## 1. Why the current evaluation is weak as a security study

The §5.1 detection results (SG1–SG3, 30 iterations each, 100% / 0% FP) are
**deterministic functional-conformance checks of the state machine**, not
adversarial tests:

- **SG1 / SG2** are happy-path assertions: a trusted device is allowed, and a
  new device that *receives a valid approval* is allowed.
- **SG3** ("attacker → BLOCK") does not actually attack the protocol. In
  `backend/scripts/sim_detection.ts` (`uc3_cloudCompromise`), the "attacker"
  simply presents a **different, unregistered DBK** and is routed to
  `NEW_DEVICE` / `PENDING`. It is blocked by **policy** (unknown device, no
  approval) — see `backend/routes/device.ts:328-357` — and never because a
  cryptographic defense repelled a forgery or replay. The signature the attacker
  submits is over *its own* key and verifies fine (`device.ts:205-209`).

Because every scenario walks an intended branch of the state machine, the
100% / 0%-FP outcome is true **by construction**. The paper already concedes
this in §5.1 ("the evaluation mainly confirms that the DLA state machine and
cryptographic decision logic behave as intended … not a general open-world
benchmark"). For a security claim, that is the gap: the experiments never try to
**break** the device binding, the approval signature, or the single-use
challenge — exactly the properties that make DLA more than passkey-alone.

This matters most for the central contribution: DLA's security rests on the
claim that the **approval signature is unforgeable and tightly bound** (to
`requestId`, `requestingDeviceId`, `approverDeviceId`, `loginAttemptId`,
`decision`, `approvalNonce` — `device.ts:543-551`) and that DBK proofs are
**single-use** (challenge consumed from the session, `device.ts:127-128`). None
of that is currently exercised.

## 2. Proposed adversarial test matrix

Each row is a negative test runnable against the real backend; each asserts not
just "blocked" but **which layer/reason** rejected it. All map to verified
branches in `routes/device.ts`.

| # | Attack class | Concrete action | Expected rejection (layer / reason) | Code anchor |
|---|---|---|---|---|
| A1 | **Forged approval** | A PENDING/attacker device signs the approval payload with *its own* DBK key | `verifyDbkSignatureOverMessage` fails → 403 `Invalid DBK signature` | `device.ts:558-576` |
| A2 | **Wrong signer** | A second untrusted (PENDING) device tries to approve a third device | `requireAuthenticated` + `deviceStatus==TRUSTED` + `approverDeviceId` binding → 403 | `device.ts:504-532` |
| A3 | **Decision flip** | Reuse a valid `DENIED` signature but submit `decision=APPROVED` | `decision` is inside the signed payload → signature mismatch → 403 | `device.ts:549` |
| A4 | **Signature transplant** | Replay a valid approval signature against a *different* `requestId` | `requestId` + `approvalNonce` in payload → signature mismatch → 403 | `device.ts:545,550` |
| A5 | **Approval replay** | Re-submit an already-used/decided approval | status guard `!= PENDING` → 409; finalize requires `APPROVED`→`CONSUMED` | `device.ts:533-536`, `:712-715` |
| A6 | **Challenge replay** | Reuse a previously valid DBK-proof signature for a second `/verify` | challenge is single-use (deleted from session on consume) | `device.ts:127-128` |
| A7 | **Challenge expiry** | Sign and submit after the 120 s window | expiry check → 401 | `device.ts:139-149` |
| A8 | **Key substitution** | An existing device re-submits a *new* DBK public key at `/challenge` | server verifies against the **stored** key, ignoring the client key | `device.ts:177-183` |
| A9 | **Cross-user replay** | Use device A's challenge/approval inside user B's session | `userId` binding in challenge/session and approval lookup | `device.ts:135-138`, `:524-532` |

### Negative controls (show each binding is load-bearing)

For A3/A4, take a *genuinely valid* approval signature and mutate exactly **one**
bound field at a time (`requestId`, `requestingDeviceId`, `approverDeviceId`,
`loginAttemptId`, `decision`, `approvalNonce`). Each single-field mutation must
flip the result from ACCEPT to REJECT. This demonstrates that every field in the
canonical payload is actually enforced, rather than decorative — a much stronger
statement than "the happy path passes."

### Suggested results-table format (replaces all-pass Table III)

| Attack | Trials | Blocked | Rejecting layer | Notes |
|---|---|---|---|---|
| A1 Forged approval | 30 | 30/30 | signature verify | — |
| A3 Decision flip | 30 | 30/30 | signature verify | payload binds `decision` |
| A5 Approval replay | 30 | 30/30 | status guard | `CONSUMED` is terminal |
| … | | | | |

Reporting *why* each attack failed (and which layer caught it) gives the reader
security insight that a uniform "30/30 BLOCK" cannot.

## 3. Reporting / wording fixes for §5

1. **Separate the two evaluations.** Detection results come from a Node
   simulation (`@dla.sim` synthetic users, in-process `CookieJar`), while the
   latency tables (IV–VII) come from real Android devices. Present them as two
   distinct studies — "protocol conformance (simulation)" vs. "latency on real
   devices" — and don't let the abstract/§5 phrasing ("we implemented DLA on
   the real Android devices and evaluated … flows") imply the *detection* numbers
   were collected on phones.
2. **Scope Table III honestly.** Its title already says "from simulation
   testing"; pair it with an explicit statement that it validates the state
   machine under the stated threat model, and add the adversarial matrix above
   as the actual *security* evaluation.
3. **Frame the security claim around the bindings**, not the labels: show that
   forgery/replay/transplant fail because of the signed canonical payload and
   single-use challenge, with the negative-control evidence.

## 4. Status

This note is documentation only — the adversarial suite is **not** implemented
in code (per scope decision). The two functional bugs that previously prevented
the *honest* approval path from working end-to-end have been fixed separately:

- Android now signs the server's exact canonical approval payload
  (`app/.../DLAAuthManager.kt`, `app/.../model/Models.kt`).
- `sim_detection.ts` now signs the approval decision so UC2/UC4 exercise the
  real signature-verification path (previously it sent no signature, which the
  current server rejects with 400).
