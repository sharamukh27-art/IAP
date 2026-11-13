# IoT AFTERLIFE PROTOCOL — Project Presentation

## The Problem: Devices Outlive Vendor Support

Connected IoT devices — smart cameras, door locks, thermostats, baby monitors — remain in homes and organisations for years after their manufacturer stops providing security updates. This creates a growing population of **orphaned devices**: devices with known, unpatched vulnerabilities, no official support path, and no safe way for owners to protect themselves.

Current approaches fail in three ways:
1. **No visibility.** There is no authoritative record of when vendor support ends or what vulnerabilities exist.
2. **No governance.** Community firmware exists, but there is no verified, traceable chain from a vulnerability to a tested, approved patch.
3. **No protection.** Even when patches exist, there is no mechanism to verify that what lands on the device matches what was reviewed.

---

## The Proposed Solution

The IoT Afterlife Protocol proposes a governance lifecycle for post-support IoT devices:

1. **Device passports** record explicit support dates, firmware identity, known vulnerabilities, and recovery capability — not inferred from device age.
2. **Evidence-based orphan verification** requires multiple independent signals and a reviewer quorum before any device is classified as abandoned.
3. **Community patches** are accepted only after automated safety testing, independent reviewer approval, cryptographic release authorization, and post-update verification.
4. **A virtual Guardian** enforces network restrictions and verifies firmware identity before restoring a device to normal operation.

The result is a traceable, fail-closed lifecycle with an on-chain audit record.

---

## Architecture

```
React/Vite UI ──Bearer token──► FastAPI REST API
                                       │
                        ┌──────────────┼──────────────┐
                        │              │              │
                     MongoDB    Local Hardhat    Mosquitto MQTT
                   (device,      blockchain     (loopback broker)
                    orphan,      contract           │
                    patches,                   ┌────┴────┐
                    users)                  Guardian  Gateway
                                            Agents    (virtual)
```

**Key trust boundaries:**
- The browser holds only a short-lived HMAC-signed token in sessionStorage. All auth and role checks are server-side.
- Firmware bytes live in local off-chain storage. Only their SHA-256 is copied on-chain.
- The community Ed25519 private key never leaves the backend server.
- The MQTT broker binds to loopback only; the gateway never opens external sockets.

**Tech stack:**
- Backend: Python 3.9+, FastAPI, MongoDB (via pymongo), paho-mqtt, cryptography, web3.py
- Contract: Solidity 0.8, Hardhat 3
- Frontend: React 18, Vite 6, TypeScript 5, Tailwind CSS 3, React Router 7

---

## End-to-End Lifecycle

| Step | Description | Key guarantee |
|---|---|---|
| 1 | Manufacturer registers device | Passport records explicit support end date |
| 2 | Manufacturer announces end of support | Evidence signal recorded |
| 3 | Orphan engine collects multiple signals | Requires ≥3 distinct signals including lifecycle + corroborating |
| 4 | Administrator submits orphan claim | 60-second challenge window opens |
| 5 | Two independent reviewers attest | Each reviewer authenticated separately |
| 6 | Administrator finalizes | Evidence re-evaluated at finalization |
| 7 | Security researcher submits patch | 8 automated lab checks run on actual bytes |
| 8 | Two independent reviewers approve | Failed patches cannot enter review queue |
| 9 | Administrator releases with signature | Ed25519 signature verified over exact bytes; on-chain |
| 10 | Guardian verifies and installs | 6 checks: hash, signature, chain record, compatibility, vulns, post-update |
| 11 | Gateway policy restored | Only after all 6 recovery checks pass |
| 12 | Dashboard shows community maintained | All numbers from real MongoDB records |

---

## What is Novel in This Prototype

1. **Traceable lifecycle.** The prototype connects evidence collection, multi-party governance, cryptographic patch release, and post-update protection in one auditable chain — from support announcement to firmware change.

2. **Fail-closed by design.** Every gate requires positive evidence to advance. A missing signature, a failed lab check, an unmatched hash, or a revoked on-chain authorization stops the workflow. There is no "skip for demo" mode.

3. **Separation of evidence and verification.** Orphan classification requires multiple independent signal types. A single endpoint outage or stale update date cannot classify a device as abandoned.

4. **Community patch with cryptographic traceability.** Patches carry a SHA-256 from submission through on-chain record to Guardian recovery. The hash used in the firmware release transaction is the same one verified during installation.

**This is a project integration contribution, not a claim of scientific novelty or a certified security method.**

---

## Validation

| Layer | Method | Result |
|---|---|---|
| Backend Python | pytest with mongomock | 125 tests, 0 failures |
| Solidity contract | Hardhat Mocha | 9 tests, 0 failures |
| Frontend | TypeScript strict + Vite production build | 0 type errors, clean build |
| Security audit | 84 new audit-focused tests | 4 bugs found and fixed |

---

## Future Scope

| Area | Extension |
|---|---|
| Real device integration | Replace simulated evidence with actual manufacturer EoL feeds, CVE databases, and firmware update endpoints |
| Production identity | Replace the custom HMAC token with OAuth 2.0 / OIDC and a verified organization identity layer |
| Key management | Move the community signing key to an HSM; implement key rotation and multi-signature release |
| Extended malware analysis | Add sandboxed execution, entropy analysis, and YARA rule scanning |
| Long challenge periods | Extend the orphan challenge period from 60 seconds to 30+ days for production governance |
| Decentralized governance | Replace the simulated reviewer registry with a DAI-style voting system |
| Public permissioned chain | Move from Hardhat localhost to a permissioned chain shared among manufacturer and reviewer organizations |
| Native MQTT security | Add TLS and certificate-based authentication to the MQTT broker |

---

## Simulation Notice

All devices, manufacturers, vulnerabilities, firmware payloads, reviewer identities, and attack simulations are fictional. No physical IoT device is modified. No real manufacturer or vendor is implied. The blockchain is a local development chain that resets on restart. This prototype is for demonstration and academic evaluation only.
