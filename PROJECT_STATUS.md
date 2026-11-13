# Project Status — IoT AFTERLIFE PROTOCOL

## Phase 1 — Device Digital Identity & Security Passport

- [x] MongoDB-backed device registry and six fictional-device seed data
- [x] FastAPI list, create, retrieve, replace, and partial-update endpoints
- [x] Manufacturer, compatibility, support-status, and risk filters
- [x] Deterministic compatibility classification and documented score breakdown
- [x] React/Vite/TypeScript/Tailwind registry and passport pages
- [x] API endpoint tests: 4 passing against an isolated Mongo-compatible test collection
- [x] Backend tests (4 passing), Python syntax check, frontend production build, and npm dependency audit (0 vulnerabilities)
- [ ] Run against a live MongoDB instance (Docker is not available in the current environment)
- [ ] Manually verify in a browser

## Phase 2 — Autonomous Orphan Detection Engine

- [x] Six-signal evidence collector with multi-signal candidate criteria
- [x] MongoDB-backed evidence snapshots, scenario state, attestations, and audit history
- [x] Supported → at-risk → candidate → pending → verified/disputed lifecycle
- [x] Challenge period and two-distinct-reviewer quorum before verification
- [x] Fictional manufacturer shutdown, end-of-support, maintenance failure, and reset controls
- [x] Connected React Orphan Detection Center with evidence and administrator workflow
- [x] False-positive/false-negative engine tests and endpoint workflow tests
- [x] Backend tests (13 passing), Python syntax check, frontend production build, and npm dependency audit (0 vulnerabilities)
- [ ] Run against a live MongoDB instance (Docker is not available in the current environment)
- [ ] Manually verify in a browser

The challenge period defaults to 60 seconds. Evidence sources are simulated; claim and reviewer actor identities are bound to authenticated accounts. No real manufacturer endpoint is probed.

## Phase 3 — Community Patch Marketplace & Patch Safety Laboratory

- [x] Server-hashed bounded JSON uploads stored off-database as local files
- [x] Eight-check safe synthetic patch laboratory; uploaded payloads are never executed
- [x] Valid and malicious/incompatible sample packages
- [x] Verified-orphan-only patch eligibility and researcher profiles
- [x] Server-side researcher, reviewer, and admin role checks
- [x] Two-distinct-reviewer quorum, mandatory rejection reasons, and separate admin release
- [x] Researcher reputation awarded only for released patches
- [x] Marketplace, submission, patch detail, testing results, profiles, and reviewer approval pages
- [x] Backend tests (21 passing), Python syntax check, frontend production build, and npm dependency audit (0 vulnerabilities)
- [ ] Run against a live MongoDB instance (Docker is not available in the current environment)
- [ ] Manually verify full orphan-to-release workflow in a browser

Patch workflow routes now use Phase 6 authenticated roles. The application remains a local prototype, not a production identity provider.

## Phase 4 — Blockchain Governance & Security Inheritance Protocol

- [x] Solidity governance contract with device/firmware identity, support dates, orphan decisions, patch decisions, recovery authorization, firmware release hashes, and history events
- [x] Three assigned reviewers per device with two-of-three decisions and a 60-second on-chain orphan challenge
- [x] Community maintainer proposal, independent reviewer quorum, per-device authorization, revocation, emergency pause, and recovery revocation
- [x] Repeated proposal rounds use unique nonces; reversing orphan verification revokes recovery authorization
- [x] Hardhat 3 local deployment registers the six foundation devices and two Aster demo cameras, with the approved demo maintainer
- [x] FastAPI local JSON-RPC integration checks loopback RPC, chain ID, deployed contract bytecode, unlocked development actors, and successful transaction receipts
- [x] Orphan claims/attestations/finalization and tested patch submissions/reviews/releases are submitted as actual local-chain transactions
- [x] Stored patch bytes are re-hashed before release; the API verifies a separate community Ed25519 signature before on-chain release
- [x] Generated private signing key and deployment metadata are git-ignored; private keys are never sent to the frontend or written on-chain
- [x] React Blockchain Audit Explorer reads mined contract logs, transaction hashes, block timestamps, and filters by readable device ID
- [x] Seven Hardhat contract tests pass, including unauthorized patch approval denial, threshold/challenge enforcement, nonce reuse, and emergency revocation
- [x] Backend suite: 24 passing; frontend production build passes; Hardhat dependency audit: 0 known vulnerabilities
- [x] Local Hardhat RPC deployment and full orphan → patch test → two-review approval → Ed25519-signed release integration workflow verified
- [ ] Run against a live MongoDB instance and manually verify the browser workflow

The local blockchain uses unlocked Hardhat test accounts and is for development only. Simulated reviewer/admin identities are not production authentication. Contract history is local to the node and resets when the node is restarted; rerun the deployment script after starting a fresh node.

## Phase 5 — Guardian Shield: Autonomous Device Protection

- [x] Per-device Python Guardian Agent receives backend policy and recovery notifications over MQTT.
- [x] Mosquitto service configured for local-only development; Paho MQTT publisher, virtual-agent subscriber, and gateway subscriber added.
- [x] Deterministic NORMAL / RESTRICTED / QUARANTINED policy engine based on maintenance, support date, orphan state, vulnerability severity, isolation capability, and firmware authenticity.
- [x] Simulated gateway permits/denies only virtual destinations, logs blocked attempts, and never opens external sockets.
- [x] Recovery checks exact stored firmware bytes, SHA-256, community Ed25519 signature, mined firmware release event, target model/revision, vulnerability fixes, and virtual post-update tests.
- [x] Successful recovery records RECOVERY VERIFIED, updates the simulated firmware identity, then publishes NORMAL gateway permissions; failed verification leaves the previous firmware and restrictive permissions intact.
- [x] React Guardian Shield dashboard shows device protection, MQTT health, firmware checks, network decisions, recovery status, blocked attempts, and event history.
- [x] Recovery, signature, compatibility, post-update, gateway, and agent-flow tests added.
- [x] Backend suite: 33 passing; Python syntax check and frontend production build pass.
- [x] Live Mosquitto 2.1.2 publish/subscribe, agent, gateway, event, and recovery-notification integration checked with Mongomock.
- [ ] Run against a live MongoDB/Hardhat stack and manually verify the browser flow.

The Mosquitto demonstration config allows anonymous MQTT but binds only to loopback. Do not expose it outside a trusted local development environment.

## Phase 6 — IoT Afterlife Command Center

- [x] Bootstrap administrator, scrypt password hashes, HMAC-signed expiring bearer tokens, sign-in/current-user and account activation endpoints
- [x] Server-enforced role authorization for administrator, manufacturer, security researcher, independent reviewer and device owner
- [x] Manufacturer and device-owner record scopes; workflow actor IDs must match authenticated identities
- [x] Manufacturer support-announcement control limited to its own fictional manufacturer; outage simulations and lifecycle verification remain administrator controlled
- [x] Live `/api/command-center` aggregates for registered/supported/orphaned/risk/quarantined devices, approved patches, recoveries, failed attempts, scores and recent stored events
- [x] Live `/api/analytics` reports for scores, orphan trends, vulnerability severity, patch testing, recovery rate/time and quarantine events
- [x] Responsive React command center, full section navigation, passport directory, patch-lab report, analytics, authentication and administrator user-management screens
- [x] Three Aster Devices virtual cameras included in both MongoDB seed data and local-chain deployment
- [x] Firmware release fails closed without a local chain submission and verified Ed25519 signature
- [x] Architecture diagram and end-to-end manufacturer-to-recovery demonstration guide
- [x] Demo Scenario page (interactive step-by-step guide within the UI at `/demo`)
- [x] Seed script creates all 7 demo user accounts automatically (idempotent, default password configurable via `SEED_DEMO_PASSWORD`)
- [x] `mosquitto.conf` binds to `127.0.0.1` only (loopback-only, never `0.0.0.0`)
- [x] `.env.example` updated with `SEED_DEMO_PASSWORD` placeholder
- [x] Authentication, role-scope, data aggregation and workflow regression tests; full backend suite: 41 passing
- [x] Frontend TypeScript check and production build pass
- [ ] Start MongoDB, Mosquitto and local Hardhat together and verify the full browser-based end-to-end flow; Docker is not installed in the current environment

## Security and Functionality Audit (Post Phase 6)

- [x] 84 new audit tests covering all checklist items (authentication, roles, scoring, upload security, firmware/signature verification, unauthorized approval, orphan workflows, gateway policy, analytics accuracy, injection/validation, blockchain, virtual device, API edge cases)
- [x] 4 bugs found and fixed:
  - `scoring.py` unknown severity value raised `KeyError` → fixed with `.get(severity, 0)`
  - `scoring.py` unknown `network_protection` value raised `KeyError` → fixed with `.get(protection, 0)`
  - `blockchain_api.py` `/api/blockchain/history` returned 503 instead of `{"available": false}` → fixed to match `/status` behavior
  - `mosquitto.conf` bound to `0.0.0.0` → fixed to `127.0.0.1`
- [x] Full test suite: **125 Python tests + 9 Hardhat tests = 134 total, all passing**
- [x] Audit report: `docs/AUDIT_REPORT.md`
- [x] Known limitations documented: `docs/KNOWN_LIMITATIONS.md`
- [x] Project presentation: `docs/PROJECT_PRESENTATION.md`
- [x] Frontend TypeScript check and production build pass after all backend fixes
