# IoT AFTERLIFE PROTOCOL — Integrated Command Center

A software-only prototype for virtual device security passports, evidence-based orphan detection, community patch testing, local blockchain governance, and MQTT-based simulated protection. The integrated command center and analytics use live MongoDB records. Firmware package bytes stay in local off-chain storage, and the Hardhat contract records actual local-network transactions and hashes.

## Architecture

- **MongoDB** stores the device registry, evidence, patch workflows, Guardian events, user accounts and authentication state; the seed command upserts the six foundation devices plus two Aster cameras for the three-camera end-to-end demo.
- **FastAPI** provides CRUD and filter endpoints. Swagger/OpenAPI is available at `/docs`.
- **Passport service** calculates compatibility and score breakdown from each stored record. It does not infer abandonment from age: support is determined only by the explicit support-end date.
- **Orphan detection engine** stores a per-device evidence snapshot and audit log in MongoDB. A candidate needs at least three distinct signals, including at least one lifecycle signal and one corroborating service/security signal. Endpoint failure or stale updates alone can only mark a device at risk.
- **Verification workflow** requires a submitted claim, a challenge window, two distinct authenticated reviewer votes, and a final evidence re-check before an orphan can be verified.
- **Patch Safety Laboratory** hashes uploaded bytes server-side, keeps the file off MongoDB, and only parses a bounded synthetic JSON package. It runs eight deterministic checks; uploaded content is never executed on the host or in a container.
- **Patch review** requires all automated tests to pass, two distinct authenticated reviewer profiles, and a separate administrator release action. Release requires a confirmed local-chain patch submission, verified file hash, and Ed25519 signature. Reputation is awarded only for released patches.
- **Local blockchain governance** uses Solidity and Hardhat. Device registrations are seeded on-chain; orphan proposals and reviewer votes, patch submissions and approvals, recovery authorization, and releases are sent through the local JSON-RPC node. Explorer records come from mined contract logs.
- **Firmware signing** uses a separate community Ed25519 key generated locally at deployment. The API re-hashes stored file bytes and verifies the maintainer signature before release; the private key is ignored by Git and never sent to the browser or written on-chain.
- **Guardian Shield** creates a Python Guardian Agent for each registered virtual device and a separate simulated gateway. Paho MQTT carries backend policies, device connection attempts, gateway decisions, recovery notifications, and Guardian events through a local Mosquitto broker.
- The gateway makes decisions only about simulated hostnames; it never opens a socket to a destination. Restricted devices can reach the virtual local network only, quarantined devices are isolated, and suspicious host patterns are always blocked.
- Recovery requires an actually released patch, a matching mined `FirmwareReleased` event, the exact stored-file SHA-256, the configured community Ed25519 signature, model/hardware compatibility, vulnerability remediation, and passing virtual post-update checks. Only then does the backend update the simulated firmware record and publish a normal-access policy.
- **Role-based authentication** uses scrypt password hashes, HMAC-signed bearer tokens, server-side role checks, manufacturer scoping, and per-device owner scoping. The bootstrap administrator is created from environment variables; new users and researcher/reviewer profiles are provisioned by an administrator.
- **Command Center and risk analytics** aggregate persisted device scores, orphan audit entries, patch tests, Guardian state/events, and blocked gateway logs. Empty collections stay empty; dashboard values are not seeded demo counters.
- **React/Vite** provides the responsive command center, registry, individual passports, orphan center, marketplace, testing lab, Guardian, blockchain explorer, analytics, sign-in, and user-management pages. The Vite development server proxies `/api` to FastAPI.
- Devices, manufacturers, outage scenarios, reviewer identities, vulnerabilities, simulated firmware capabilities, and patch payloads are fictional data only. No physical hardware or external vulnerability scan is used.

See the [architecture diagram](./architecture.md) and [end-to-end demonstration guide](./docs/DEMO_GUIDE.md).
For a complete clean-install walkthrough, see the [installation guide](./docs/INSTALLATION_GUIDE.md). Audit results, a timed five-minute walkthrough, and a project presentation are in [the audit report](./docs/AUDIT_REPORT.md), [the demo script](./docs/FIVE_MINUTE_DEMO.md), and [the presentation outline](./docs/PROJECT_PRESENTATION.md). Known limitations are in [KNOWN_LIMITATIONS.md](./docs/KNOWN_LIMITATIONS.md).

## Requirements

- Python 3.9+
- Node.js 22.13+ (Hardhat 3 requirement)
- MongoDB 7+ locally, or Docker Compose
- Mosquitto 2+ (included in the Docker Compose setup)

## Run locally

From the project directory:

1. Copy `.env.example` to `.env`. Replace both `AUTH_SECRET_KEY` and `AUTH_BOOTSTRAP_ADMIN_PASSWORD` with unique values before starting the API. Generate a secret with `python3 -c 'import secrets; print(secrets.token_urlsafe(48))'`; the bootstrap password must have at least 12 characters.
2. Start MongoDB and the loopback-only Mosquitto broker with `docker compose up -d mongo mosquitto` (or start compatible local services).
3. Install and test the Hardhat project:

   ```bash
   cd chain
   npm install
   npm run compile
   npm test
   ```

4. In a separate terminal, start the local chain and deploy the contract:

   ```bash
   cd chain
   npm run node
   ```

   In another terminal:

   ```bash
   cd chain
   npm run deploy:local
   ```

   Deployment registers all eight fictional devices and records the 2-of-3 reviewer approval that authorizes the local community maintainer. It writes the contract address, ABI, actor addresses, and Ed25519 public key to the ignored `backend/app/blockchain_deployment.json`. The separate Ed25519 private key is generated in `backend/storage/keys/` and is never exported to the frontend or on-chain.

5. Start the API and seed MongoDB:

   ```bash
   cd backend
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   set -a && source ../.env && set +a
   python -m app.seed
   uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

   `python -m app.seed` upserts the 8 virtual devices and creates 7 demo user accounts (manufacturer, researcher, reviewer ×3, device owner) with the password from `SEED_DEMO_PASSWORD` (default `DemoPassword123!` — change before sharing). It never overwrites existing accounts or workflow history.

6. In another terminal, start the UI:

   ```bash
   cd frontend
   npm install
   npm run dev
   ```

7. Open <http://localhost:5173>. API documentation: <http://localhost:8000/docs>.

Sign in as the bootstrap administrator using the username and password from `.env`. Use **Settings & Users** to create scoped fictional manufacturer, researcher, reviewer, and device-owner accounts. Alternatively, the seed command creates all demo accounts automatically. Open the **Demo Scenario** tab for a step-by-step guide through the complete IoT lifecycle. The token is held in browser `sessionStorage` only. All `/api` routes other than `/health`, `/api/auth/login`, and the OpenAPI documentation require a bearer token.

The API reads `MONGODB_URI`, `MONGODB_DATABASE`, `BLOCKCHAIN_RPC_URL`, and `BLOCKCHAIN_DEPLOYMENT_FILE` from the process environment. The example deployment/key paths are relative to the `backend` working directory. The blockchain connector only permits loopback RPC URLs and checks the configured chain ID and contract bytecode. If the node is stopped or deployment is missing, the explorer reports that state and displays no fabricated chain records.

## API

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/api/auth/login` | Verify username/password and issue a short-lived bearer token |
| `GET` | `/api/auth/me` | Resolve the authenticated account and current role |
| `GET` | `/api/auth/users` | Administrator-only account directory |
| `POST` | `/api/auth/users` | Administrator-only account provisioning, including manufacturer/device scopes |
| `PATCH` | `/api/auth/users/{user_id}` | Administrator-only account enable/disable |
| `GET` | `/api/command-center` | Live dashboard metrics and recent persisted security events |
| `GET` | `/api/analytics` | Live survival, orphan, vulnerability, patch, recovery and quarantine reports |
| `GET` | `/api/devices` | List devices; optional `manufacturer`, `compatibility_category`, `support_status`, and `risk_level` filters |
| `POST` | `/api/devices` | Register a device |
| `GET` | `/api/devices/{device_id}` | Retrieve a device passport |
| `PUT` | `/api/devices/{device_id}` | Replace editable device fields |
| `PATCH` | `/api/devices/{device_id}` | Update selected editable fields |
| `GET` | `/api/orphans/dashboard` | Orphan Detection Center counters and evidence cases |
| `GET` | `/api/orphans` | List evidence cases; optional lifecycle `state` filter |
| `GET` | `/api/orphans/{device_id}` | Retrieve a device's evidence record |
| `POST` | `/api/orphans/scan` | Refresh evidence and lifecycle classifications |
| `POST` | `/api/orphans/simulations` | Apply a fictional manufacturer's simulation scenario |
| `POST` | `/api/orphans/{device_id}/claims` | Submit an orphan candidate for review and start challenge |
| `POST` | `/api/orphans/{device_id}/attestations` | Record an authenticated independent reviewer vote |
| `POST` | `/api/orphans/{device_id}/finalize` | Finalize after challenge and quorum checks |
| `GET` | `/api/patches` | Marketplace listing; optional `status_filter` |
| `GET` | `/api/patches/eligible-devices` | Devices with Verified Orphan status eligible for community patches |
| `POST` | `/api/patches` | Multipart patch submission; server hashes and tests actual uploaded bytes |
| `GET` | `/api/patches/{patch_id}` | Patch details, test report, reviews, and audit history |
| `POST` | `/api/patches/{patch_id}/reviews` | Authorized reviewer decision; rejection requires a reason |
| `POST` | `/api/patches/{patch_id}/release` | Administrator release after tests, reviewer quorum, chain submission and signature verification |
| `GET` | `/api/patches/sample-packages` | Safe demonstration package metadata |
| `GET` | `/api/patches/sample-packages/{filename}` | Download one of the allowlisted JSON demonstrations |
| `GET` | `/api/researchers` | Researcher and reviewer directory; optional role filter |
| `POST` | `/api/researchers` | Administrator-only profile creation; normal provisioning uses `/api/auth/users` |
| `GET` | `/api/researchers/{researcher_id}` | Researcher reputation and released contributions |
| `GET` | `/api/blockchain/status` | Local chain/deployment health, contract address, and policy |
| `GET` | `/api/blockchain/history` | Real contract event history; optional `device_id` filter |
| `GET` | `/api/guardian` | Guardian protection states, MQTT status, gateway counters, and event timeline |
| `GET` | `/api/guardian/events` | Recent Guardian and gateway events; `limit` from 1–200 |
| `POST` | `/api/guardian/devices/{device_id}/network-attempts` | Ask a virtual device to request a simulated host through the MQTT gateway |
| `POST` | `/api/guardian/devices/{device_id}/recoveries` | Administrator-only Guardian recovery notification and verification |
| `GET` | `/health` | API health check |

Interactive request/response documentation is generated at `/docs`; the OpenAPI JSON is at `/openapi.json`. All operations require a bearer token except health, login and API documentation. Manufacturer users are scoped to their manufacturer; device owners are scoped to assigned device IDs. Device writes are administrator/manufacturer only; manufacturer support announcements are limited to that user's own manufacturer; orphan verification is administrator/reviewer only; patch submissions are security-researcher only; patch votes are independent-reviewer only; release/user management are administrator only. Actor IDs in workflow requests must match the authenticated account.

To use the API from a local shell, log in and pass the returned token:

```bash
TOKEN="$(curl -sS http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"patch-admin-demo","password":"<your .env bootstrap password>"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/command-center
```

## Classification and survival score

Classification is rule-based and uses explicit device capabilities:

1. **Community Recoverable** — `supports_alternative_firmware` is true.
2. **Gateway Protectable** — otherwise, both `gateway_protection_available` and `safe_to_isolate` are true.
3. **Unsafe to Maintain** — neither safe recovery nor adequate gateway isolation is available.

The Device Survival Score is the sum of five disclosed factors, clamped to 0–100:

| Factor | Points |
|---|---:|
| Vendor security support is active on the evaluation date | 25, otherwise 0 |
| Firmware authenticity is verified | 20, otherwise 0 |
| Recovery/protection path | 15 for community firmware; 8 for an available safe gateway path; otherwise 0 |
| Network protection | 15 if protected; 8 if isolated; otherwise 0 |
| Unpatched known vulnerabilities | Start at 25; subtract 10 per critical, 6 per high, 3 per medium, and 1 per low finding; floor at 0 |

Risk is **Low** for scores ≥80, **Medium** for scores 60–79, and **High** below 60. Support status is derived from the explicit `security_support_end_date` (not device age or time since last update). Vulnerability and authenticity values are seeded simulation evidence, not a real-world scan or cryptographic firmware validation.

## Orphan detection and verification (Phase 2)

The detector records six signal types per device:

1. Fictional official end-of-life/support announcement.
2. Explicit support-end date passed.
3. Firmware update date is more than 365 days old.
4. Simulated manufacturer maintenance endpoint unavailable.
5. Simulated security certificate expired.
6. At least one recorded vulnerability is unpatched.

No single signal can create an orphan candidate. A candidate needs **3 or more distinct active signals**, including one lifecycle signal (announcement, passed support date, or stale updates) and one corroborating signal (endpoint, certificate, or unpatched vulnerability). Fewer signals result in **Support At Risk**; no signals result in **Supported**.

Candidate claims start a challenge period (`ORPHAN_CHALLENGE_SECONDS`, 60 seconds by default for the software demo). Finalization re-evaluates the evidence and requires two matching votes from different authenticated independent reviewers. Two approvals produce **Verified Orphan**; two rejections or evidence failure produce **Disputed / Verification Failed**. Evidence remains synthetic and does not probe real manufacturer endpoints.

The simulation control accepts `manufacturer_shutdown`, `end_of_support`, `maintenance_failure`, and `reset` for the fictional manufacturers seeded in Phase 1. Shutdown creates multiple explicit simulated signals. A maintenance endpoint outage alone remains at risk, not orphaned.

### Phase 2 API examples

These examples assume `TOKEN` is set as in the authenticated API section above.

```bash
# See device/case totals and current evidence
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/orphans/dashboard

# Simulate a fictional vendor shutdown
curl -X POST http://localhost:8000/api/orphans/simulations \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"manufacturer":"Aster Devices","scenario":"manufacturer_shutdown","actor":"patch-admin-demo"}'

# Claim an eligible candidate
curl -X POST http://localhost:8000/api/orphans/CAM-B-002/claims \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"submitted_by":"patch-admin-demo","note":"Multiple simulated lifecycle and security signals corroborate the claim."}'

# Record two distinct reviewer approvals, then wait for the challenge and finalize
curl -X POST http://localhost:8000/api/orphans/CAM-B-002/attestations \
  -H "Authorization: Bearer $REVIEWER_ADA_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reviewer_id":"reviewer-ada","decision":"approve","note":"Evidence reviewed."}'
curl -X POST http://localhost:8000/api/orphans/CAM-B-002/attestations \
  -H "Authorization: Bearer $REVIEWER_LINUS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reviewer_id":"reviewer-linus","decision":"approve","note":"Independent review complete."}'
curl -X POST http://localhost:8000/api/orphans/CAM-B-002/finalize \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"actor":"patch-admin-demo"}'
```

In the UI, open **Orphan detection** in the top navigation, choose a fictional manufacturer and scenario, then select the resulting candidate to submit a claim, collect reviewer attestations, and finalize after the displayed challenge countdown.

## Community patch marketplace and safety lab (Phase 3)

### Package format and safe testing boundary

The only accepted upload is a `.json` file up to 1 MiB. The lab validates UTF-8/JSON and the `iap-synthetic-firmware-v1` schema, checks compatibility/remediation metadata, and scans content for fixed suspicious strings. Fixed backend regression and virtual-device test scripts compare declared synthetic capabilities against required model-specific features and security behaviours; they do not accept a single uploader-provided pass/fail flag. The pipeline never unpacks archives, invokes a shell, imports package code, executes a binary, or launches arbitrary uploaded firmware. The eight checks are:

1. **File integrity** — SHA-256 is calculated from the exact uploaded bytes; file size, extension, and synthetic JSON schema are checked. Any submitted hash form field is ignored.
2. **Firmware compatibility** — supported synthetic format and version string.
3. **Device model and hardware revision** — exact target match.
4. **Vulnerability remediation** — requested IDs must be known unpatched issues and listed in the package's remediation metadata.
5. **Malware/suspicious-file scan** — configured literal marker scan plus the package's declared suspicious-indicator list. This is a safe synthetic scan, not antivirus.
6. **Regression test** — local model-specific test script verifies required simulated legacy features are preserved and no regression failure is declared.
7. **Virtual-device behaviour** — local test script verifies required simulated authentication, encrypted control-channel, and signed-update behaviours; no uploaded code is run.
8. **Rollback** — a non-empty rollback version and synthetic payload must be declared.

The capability metadata itself is supplied by the researcher and is not cryptographically attested. Passing these checks means only that the submitted synthetic metadata satisfies the prototype's deterministic rules. It is not proof that a real firmware binary is safe, authentic, or compatible; the package does not contain executable firmware.

### Status, review, and reputation

Every patch stores its status progression and audit history. Successful tests progress through **Submitted → Testing → Passed → Awaiting Review**; any failed check produces **Failed**. Approval requires all checks passed plus **two distinct reviewer-role profiles**. Two rejections produce **Rejected**, and each rejection must include a reason. A separate authenticated administrator can release only an **Approved** patch, and release is blocked unless local blockchain governance is available with a confirmed patch submission. A release adds 10 reputation points to the submitter; submissions, failed tests, votes, or unreleased approvals add none.

Researcher/reviewer profile IDs are linked to provisioned authenticated user accounts. The local prototype uses one application HMAC secret and is not a production identity provider; do not expose it or the local chain/broker to an untrusted network.

Patch bytes are stored locally under `backend/storage/patches/` by default (or the `PATCH_STORAGE_DIR` environment variable) and patch metadata/results are stored in the `patches` MongoDB collection. The patch storage directory is git-ignored.

### Demonstration workflow

1. Verify Smart Camera B (`CAM-B-002`) as an orphan through Phase 2. Simulate an **Aster Devices** shutdown, submit the claim, obtain two distinct reviewer approvals, wait the challenge period, and finalize.
2. Sign in as an authorized researcher and open **Patch marketplace → Submit a patch**. Select the now-eligible camera, select both recorded unpatched vulnerabilities, and upload [the valid sample package](./backend/sample_patches/cam-b-community-fix-2.0.9.json). It should pass all eight synthetic checks and move to **Awaiting Review**.
3. Upload [the incompatible/malicious sample package](./backend/sample_patches/cam-b-incompatible-malicious.json) against that device. The result should be **Failed** with explicit mismatched model/revision, missing remediation, malware marker, failed regression/behaviour, and missing rollback reasons. A failed patch cannot enter approval.
4. Sign in as two different authorized reviewers and use **Review queue** to record separate approvals. Sign in as the administrator to release the approved patch. Without the chain and valid Ed25519 signature the patch must remain unreleased. Open the researcher profile to see reputation and the released contribution.

Upload endpoint example:

```bash
curl -X POST http://localhost:8000/api/patches \
  -H "Authorization: Bearer $RESEARCHER_TOKEN" \
  -F 'device_id=CAM-B-002' \
  -F 'researcher_id=researcher-ada' \
  -F 'patch_version=2.0.9-community.1' \
  -F 'description=Community patch for the two recorded camera vulnerabilities.' \
  -F 'vulnerabilities=["SIM-VULN-CAM-B-01","SIM-VULN-CAM-B-02"]' \
  -F 'patch_file=@backend/sample_patches/cam-b-community-fix-2.0.9.json;type=application/json'
```

### Phase 3 routes

The frontend includes **Patch marketplace** (`/patches`), **Submit Patch** (`/patches/submit`), **Patch Details** (`/patches/{patch_id}`), **Patch Testing Results** (`/patches/{patch_id}/tests`), **Researcher Profiles** (`/researchers` and `/researchers/{researcher_id}`), and **Reviewer Approval** (`/patch-review`).

## Blockchain Governance (Phase 4)

The local `InheritanceGovernance` contract records device and firmware identity, support end dates, orphan decisions, reviewer votes, community maintainers, patch test outcomes, approvals, recovery authorization, firmware release hashes, emergency pause/revocation, and timestamps. The deployment assigns three distinct reviewers per device; two approvals are required. An orphan decision has a 60-second on-chain challenge period. A patch must be attached to a verified orphan, pass automated tests, and receive a two-reviewer quorum. Release also requires an authorized maintainer and exact SHA-256 equality.

The contract stores metadata and hashes only, never firmware binaries or private keys. Ed25519 signs the exact locally stored synthetic package bytes using the separately generated community maintainer key. After a patch is approved, run this from `backend/` and paste the printed Base64 signature into the Reviewer Approval release form:

```bash
python -m app.sign_patch PATCH-ID
```

The command prints only the signature. Keep `backend/storage/keys/community-maintainer-ed25519.pem` private; it is local-only and Git-ignored. This demo key is separate from the manufacturer's signing authority and from Hardhat's local transaction accounts. Hardhat accounts are unlocked development accounts and are not suitable for production.

The frontend's **Blockchain** page (`/blockchain`) reads decoded events from the local contract, including real transaction hashes, mined block numbers, and timestamps. It filters by device. It is not a public explorer and makes no claims about a public network. Contract verification and authorization cannot bypass secure boot, proprietary hardware restrictions, or device-specific update limitations.

Hardhat 3 is used with the Mocha/Ethers toolbox. `chain/package.json` pins patched dependency ranges, including explicit overrides for vulnerable transitive Zod, glob, and minimatch releases; `cd chain && npm audit` should report zero known vulnerabilities.

## Guardian Shield (Phase 5)

The backend starts three MQTT roles when Mosquitto is reachable: a backend publisher/event collector, a virtual-agent subscriber, and the gateway subscriber. Each known device gets a `GuardianAgent` instance. MongoDB stores the current policy/state, security event history, and blocked-connection log. If MQTT is offline, the API still starts and the dashboard states that the broker is unavailable; network and recovery actions return HTTP 503 rather than claiming success.

Protection decisions are transparent:

- **NORMAL** — firmware is authentic, support is current or community-maintained, and the device has no unpatched vulnerability or unresolved orphan risk. Local traffic and the small synthetic external allowlist (`updates.aster.test`, `time.simulator.test`) are permitted. Suspicious host patterns are denied regardless.
- **RESTRICTED** — support has ended, an orphan claim is unresolved, a vulnerability remains, or the network is unprotected. Only simulated local-network destinations are allowed.
- **QUARANTINED** — firmware authenticity fails or a severe vulnerability cannot be safely isolated. The gateway denies network access.
- **RECOVERY PENDING** — a Guardian received a release notification over MQTT.
- **RECOVERY VERIFIED** — exact-byte hash and signature, chain release record, compatibility, vulnerability, and post-update checks pass. The simulated firmware record is updated, the state transition is recorded, and only then is the gateway policy restored to **NORMAL**.

`docker-compose.yml` binds the anonymous demonstration broker to `127.0.0.1:1883` only. Do not expose this unauthenticated prototype broker to a network. Set `MQTT_HOST`, `MQTT_PORT`, and `MQTT_CONNECT_TIMEOUT` in `.env` to override the local defaults.

### Guardian API examples

```bash
# Observe all device states and MQTT availability
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/guardian

# Simulate Smart Camera B trying to contact an unauthorized host.
# This host is evaluated by the virtual gateway; no external connection is made.
curl -X POST http://localhost:8000/api/guardian/devices/CAM-B-002/network-attempts \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"destination":"exfiltration.attacker.test","protocol":"tcp"}'

# Trigger the Guardian for a Released patch ID from the marketplace.
curl -X POST http://localhost:8000/api/guardian/devices/CAM-B-002/recoveries \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"patch_id":"PATCH-0123456789AB"}'
```

In the UI open **Guardian Shield** (`/guardian`), verify the MQTT status is connected, and use **Attempt connection** with `exfiltration.attacker.test`. The gateway should block and log it. After an eligible patch is released and signed, select it under **Released recovery package** and choose **Notify Guardian**. The checks and state transitions appear on the device card and event timeline. A modified package, invalid signature, missing chain release record, or failed post-update check leaves the device restricted/quarantined and does not update its firmware record.

## Phase 5 tests

`backend/tests/test_guardian.py` covers corrupted SHA-256, invalid Ed25519 signatures, incompatible firmware, failing post-update checks, revoked chain authorization, unauthorized host blocking, MQTT-agent command routing, and a successful recovery that updates the firmware hash and restores NORMAL policy. The automated tests use an in-memory Mongo-compatible database and do not require a live broker or MongoDB. The MQTT publish/subscribe, gateway decision, event logging, and recovery notification flow was also exercised against Mosquitto 2.1.2 with an in-memory database.

## Tests

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest
```

Tests exercise the device, orphan, researcher, patch-upload, safety lab, review, authentication, role/scope enforcement, live-data aggregation, authorization, release and reputation workflows against an isolated in-memory Mongo-compatible test collection; a running MongoDB is not required for the test suite. Frontend type-check/build: `cd frontend && npm run build`. For an end-to-end MongoDB check, start MongoDB, run `python -m app.seed`, then use the Swagger UI or dashboard.

The contract suite is run separately with `cd chain && npm test`. It includes role-denial tests for unauthorized patch approval. The backend blockchain tests exercise local RPC restrictions and Ed25519 file-signature verification. A complete local-chain orphan-to-signed-release workflow was also exercised against the deployed Hardhat node.

## Phase 6 — Integrated Command Center

- The home route is a live command center, `/devices` is the searchable registry, `/passports` is the device passport directory, and `/analytics` aggregates persisted risk, orphan, lab and recovery records.
- Navigation includes orphan detection, the community marketplace, a patch-lab report, Guardian Shield, Blockchain Audit Explorer, and administrator Settings/User Management.
- API bearer authentication is required for application endpoints. Role checks and device/manufacturer scope are enforced server-side; UI route hiding is only a usability layer.
- User passwords are scrypt-hashed. Tokens are HMAC-signed and expire. The bootstrap admin is configured only with `.env` values. User-created reviewer/researcher IDs are bound to actor identity in workflow requests.
- The database seed upserts the six Phase 1 devices and two additional Aster cameras. The local contract deployment now registers all eight.
- The command center and analytics never inject sample counts. Empty database collections produce zero counts and meaningful empty states.
- Release stays blocked without local-chain governance, a confirmed patch submission, matching uploaded-file SHA-256 and a valid Ed25519 signature.
- See [the architecture diagram](./docs/architecture.md) and [the end-to-end demonstration guide](./docs/DEMO_GUIDE.md) for role setup and the complete manufacturer-to-recovery scenario.

## Manual verification

- Sign in as the bootstrap administrator. Visit `/` for the database-backed command center and `/devices` for the registry filters.
- In **Settings & Users**, create a fictional Aster Devices manufacturer account, a researcher account, at least two independent reviewers, and a device-owner account assigned `CAM-B-002`.
- Visit `/passports` and open a card to view identity, firmware, support dates, vulnerability evidence, compatibility, and the score breakdown.
- For the complete interactive scenario, follow [the demo guide](./docs/DEMO_GUIDE.md), including two separate reviewer logins, challenge waiting, signing and recovery.
- Use `/docs` with the Swagger **Authorize** control to verify bearer-token enforcement, role denial, manufacturer scoping, and owner-device scoping.
- Confirm maintenance endpoint failure alone is not enough to mark any device a verified orphan.
- Stop the Hardhat node and confirm `/blockchain` reports unavailable without fabricated transactions and patch release is blocked.
- Confirm `LOCK-003` remains gateway-protectable rather than being represented as reflashed.

## Scope and limitations

The prototype implements virtual device identity/passports, deterministic scoring, orphan evidence lifecycle, a safe synthetic patch lab, authenticated local role accounts, local blockchain governance, Ed25519 signatures for synthetic packages, and MQTT-based simulated Guardian/gateway messaging. It does **not** implement true binary-level patch validation, physical-device scanning, live manufacturer endpoint checks, verification of real-world identities or attestations, production-grade identity infrastructure, secure-boot bypass, or enforcement on real household devices. Simulated device/evidence records must not be interpreted as real manufacturer or security claims.
