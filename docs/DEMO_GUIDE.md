# IoT AFTERLIFE PROTOCOL — End-to-End Demonstration

This walkthrough exercises the local services and actual MongoDB/Hardhat records. All devices and evidence are virtual. No physical IoT equipment or real manufacturer claims are involved.

## 1. Start a clean local stack

From the project directory:

1. Copy `.env.example` to `.env`. Set a new random `AUTH_SECRET_KEY` (at least 32 characters) and a unique `AUTH_BOOTSTRAP_ADMIN_PASSWORD` (at least 12 characters). The bootstrap username defaults to `patch-admin-demo`.
2. Start local MongoDB and the loopback-only broker:

   ```bash
   docker compose up -d mongo mosquitto
   ```

3. Install and start the Hardhat node. Keep it running:

   ```bash
   cd chain
   npm install
   npm run node
   ```

4. In a second terminal, compile/test/deploy the local governance contract:

   ```bash
   cd chain
   npm run compile
   npm test
   npm run deploy:local
   ```

   Deployment registers eight virtual device identities, sets the 2-of-3 recovery policy, and generates a separate backend-only Ed25519 community key.

5. Seed MongoDB and run FastAPI:

   ```bash
   cd backend
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   set -a && source ../.env && set +a
   python -m app.seed
   uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

6. In another terminal, run the web client:

   ```bash
   cd frontend
   npm install
   npm run dev
   ```

7. Open <http://localhost:5173>, sign in as the bootstrap administrator, and confirm the **Command Center** shows live MongoDB counts. Swagger is at <http://localhost:8000/docs>.

## 2. Provision least-privilege demo accounts

The seed command (`python -m app.seed`) creates all required demo accounts automatically with the password from `SEED_DEMO_PASSWORD` (default `DemoPassword123!`). They will not be created if accounts with those IDs already exist.

Alternatively, as the bootstrap administrator, open **Settings & Users** and create:

| Account ID | Role | Scope / use |
|---|---|---|
| `aster-support` | Manufacturer | Manufacturer scope `Aster Devices` |
| `researcher-ada` | Security Researcher | Submit synthetic patches |
| `reviewer-ada` | Independent Reviewer | First distinct vote; matches the local chain's assigned reviewer |
| `reviewer-linus` | Independent Reviewer | Second distinct vote; matches the local chain's assigned reviewer |
| `camera-owner` | Device Owner | Device scope `CAM-B-002` |

Use unique passwords for each user. The seeded researcher/reviewer profile IDs correspond to the IDs in the local patch and orphan governance policies. Sign out and sign in as each account when switching roles; request actor IDs are bound to the current account and cannot be selected in the UI.

For a visual walkthrough, open **Demo Scenario** in the navigation after signing in.

## 3. Manufacturer support announcement and orphan verification

1. Sign in as `aster-support` and open **Orphan Detection**.
2. Publish **Simulate end of support** for the scoped Aster Devices manufacturer. The announcement and support date are recorded as evidence for each of the three Aster cameras. A single signal never finalizes abandonment; inspect the evidence and candidate state.
3. Sign back in as the administrator. For each Aster camera you want to carry through the orphan workflow, open its candidate and submit a claim. Each claim starts a 60-second prototype challenge window.
4. Sign in as `reviewer-ada` and record an attestation for the selected pending camera. Sign in as `reviewer-linus` and record a second, independent attestation. Neither reviewer can vote as the other account.
5. After the countdown expires, sign in as the administrator and finalize. The state becomes **Verified Orphan** only after the backend re-check and matching quorum. Inspect the audit trail and `/blockchain` for actual transaction hashes.
6. To demonstrate why an outage is not proof, have the administrator simulate **Maintenance endpoint failure** for Hearth & Key and confirm it is not automatically declared a verified orphan.

The Phase 3 patch demonstration below uses `CAM-B-002`. To verify all three Aster cameras, repeat the claim, two reviewer votes and finalization for `AST-CAM-003` and `AST-CAM-004` as separate device cases.

## 4. Submit, test, review and release a patch

1. Sign in as `researcher-ada`, open **Patch Marketplace → Submit a patch**, choose verified orphan `CAM-B-002`, and upload `backend/sample_patches/cam-b-community-fix-2.0.9.json`. The API hashes the actual upload. Confirm all eight lab checks pass in **Patch Safety Laboratory**.
2. Submit `backend/sample_patches/cam-b-incompatible-malicious.json` for the same eligible device. Confirm **Failed** and review concrete compatibility, suspicious marker, remediation, regression/behavior and rollback failures. It must not enter reviewer approval.
3. Sign in as `reviewer-ada`, open **Reviewer Queue**, and approve the passing patch. Sign in as `reviewer-linus` and approve it independently. One reviewer or a failed lab result cannot approve a patch.
4. Sign in as the administrator. The patch is now eligible for release. In `backend/`, load `.env` and generate a signature for the exact stored package:

   ```bash
   set -a && source ../.env && set +a
   python -m app.sign_patch PATCH-ID
   ```

   Copy only the command's Base64 signature into the release form. An invalid signature is rejected; without a local chain or confirmed on-chain submission, release remains blocked. Never expose the private key.
5. Confirm the patch becomes **Released**, the contract explorer shows a mined firmware-release transaction and hash, and the researcher profile counts a verified contribution.

## 5. Guardian protection and recovery

1. Sign in as `camera-owner`, open **Guardian Shield**, and attempt `exfiltration.attacker.test` for `CAM-B-002`. The virtual gateway should block the connection and record the event. The owner can see only assigned device records.
2. Sign in as administrator, select the released `CAM-B-002` patch, and choose **Notify Guardian**.
3. Confirm Guardian verifies exact file hash, Ed25519 signature, mined release and active on-chain authorization, hardware compatibility, vulnerability remediation, and post-update checks. Only complete success updates the simulated firmware, records **RECOVERY VERIFIED**, and restores normal gateway policy.
4. To demonstrate fail-closed behavior, use the API with an invalid signature/recovery package in an isolated test record or revoke the local recovery authorization. Failed verification must not update firmware or restore network access.
5. Inspect the **Command Center**, **Risk Analytics**, **Guardian Shield** event timeline and **Blockchain Audit Explorer**. All displayed values must correspond to persisted records and local-chain receipts.
6. `LOCK-003` is **Gateway Protectable** and cannot be reflashed in this simulation. It stays under gateway restrictions; no workflow should claim it received community firmware.

## Reset and safety notes

- To reset the local Hardhat chain, stop and restart it, then rerun `npm run deploy:local`. Contract state is local to that node.
- `python -m app.seed` upserts the eight sample devices but does not erase workflow history or user accounts.
- Remove only the intended local MongoDB database/patch files if you want a fresh data set; do not expose the anonymous Mosquitto demo listener or Hardhat RPC outside loopback.
- These are deterministic simulations, not claims about real vendors, real vulnerabilities, real devices, or safe firmware for physical products.
