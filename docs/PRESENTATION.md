# IoT AFTERLIFE PROTOCOL — Project Presentation

Use this as an eight-slide presentation outline. Claims and examples below describe the local prototype, not a deployed device-security service.

## Slide 1 — The problem: devices outlive vendor support

- Connected devices can remain in homes and organizations after updates or manufacturer support stop.
- Owners often have little visibility into support status, security posture, or safe options for continued use.
- Unverified community firmware can introduce more risk than it removes.

## Slide 2 — The proposed solution

- Maintain a device passport with explicit support dates, firmware identity, compatibility, and vulnerability records.
- Treat orphan status as an evidence-backed governance decision, not an age estimate or a single failed endpoint.
- Allow community patch proposals only after a verified orphan decision and route them through tests, independent review, signed release, and recovery checks.

## Slide 3 — Architecture

- React/Vite presents the authenticated command center and workflow screens.
- FastAPI enforces authentication, role checks, manufacturer scope, and device-owner scope.
- MongoDB stores registry and workflow state; local files store bounded synthetic patch packages.
- A local Hardhat EVM records governance actions and firmware hashes.
- Loopback Mosquitto carries local messages between Python virtual agents and a simulated gateway.
- See the [architecture diagram](./architecture.md).

## Slide 4 — End-to-end lifecycle

1. Record a device passport and support information.
2. Collect multiple lifecycle and corroborating signals.
3. Submit an orphan claim, observe the challenge period, and collect two distinct reviewer votes.
4. Upload a bounded synthetic JSON package and run deterministic safety checks.
5. Obtain two independent patch approvals and administrator release.
6. Verify exact package hash, Ed25519 signature, on-chain release, compatibility, remediation, and virtual post-update tests.
7. Update simulated firmware state and gateway policy only after the checks pass.

## Slide 5 — Safety and governance controls

- Passwords use scrypt; bearer tokens use an HMAC signature and are checked against active user records on every request.
- Device authenticity and firmware identity cannot be changed through generic device CRUD; only verified recovery may update them.
- Manufacturer support updates are scoped in the API and the contract binds manufacturer names to authorized accounts.
- Patch uploads are size-limited, parsed as synthetic JSON, and never executed.
- Reviewer quorum, signature checks, exact-byte hashing, and chain authorization are checked before a simulated release.

## Slide 6 — What is novel in this prototype

- The demonstrator connects support evidence, multi-party governance, synthetic patch testing, cryptographic release records, and post-update protection in one traceable lifecycle.
- It emphasizes fail-closed behavior and explains why an outage, stale update, failed test, or missing signature is insufficient to proceed.
- This is a project integration contribution, not a claim of scientific novelty or a certified method.

## Slide 7 — Validation and demonstration

- The current audit run reports 41 passing backend tests, 9 passing Solidity tests, a successful frontend production build, and zero known issues in npm audits.
- Backend workflow tests use Mongomock; contract tests use the local Hardhat test network.
- The [five-minute demo script](./FIVE_MINUTE_DEMO.md) shows orphan verification, malicious/incompatible rejection, patch release, simulated recovery, and record traceability.

## Slide 8 — Limitations and future scope

**Current limitations**

- All devices, evidence, vulnerability records, patch packages, agents, and gateway destinations are fictional or simulated.
- No physical firmware is inspected or installed; no manufacturer endpoint or external vulnerability scanner is contacted.
- The local chain uses unlocked development accounts; the demo maps fictional manufacturer names to a shared account.
- MongoDB/EVM writes are not distributed transactions, and a live MongoDB integration check was unavailable in the audit environment.
- Authentication is prototype-grade and has no rate limiting, MFA, or production secrets-management integration.

**Future scope**

- Integrate a production identity provider, MFA, throttling, audit retention, backups, and monitored key management.
- Use independently verified manufacturer and reviewer identities with deployable governance policy.
- Add transaction reconciliation/outbox workflows for database/chain failures.
- Validate the safety model against reproducible hardware-in-the-loop tests and signed vendor/community metadata.
- Conduct independent threat modeling, privacy review, and security testing before any real-device deployment.
