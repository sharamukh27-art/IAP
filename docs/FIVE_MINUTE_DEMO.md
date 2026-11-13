# Five-Minute Demonstration Script

## Before the timer

Complete the local setup in [the installation guide](./INSTALLATION_GUIDE.md). The API, UI, MongoDB, Mosquitto, and Hardhat node must be running; seed the devices and deploy the current contract. Provision these accounts in advance:

- Manufacturer scoped to `Aster Devices`
- Researcher `researcher-ada`
- Reviewers `reviewer-ada` and `reviewer-linus`
- Device owner scoped to `CAM-B-002`

Keep the sample packages from `backend/sample_patches/` available. Do not use real device firmware or real vulnerability data.

## Live walkthrough

### 0:00–0:30 — Establish the baseline

Sign in as the administrator and show the Command Center. Explain that its device totals, risk counts, recovery totals, and recent events come from persisted local MongoDB records; a fresh installation can show empty workflow metrics.

### 0:30–0:55 — Record a lifecycle signal

Sign in as the Aster manufacturer and publish the simulated end-of-support announcement. Point out that the application records a lifecycle signal but does not automatically declare a device abandoned.

### 0:55–1:20 — Open the challenge

Return to the administrator account, open the orphan candidate for `CAM-B-002`, and submit a claim. Show the evidence list and the 60-second challenge countdown.

### 1:20–1:50 — Collect independent reviews

Sign in as `reviewer-ada` and approve the claim, then sign in as `reviewer-linus` and record the second vote. Explain that identities are authenticated platform accounts and the reviewers must be distinct.

### 1:50–2:05 — Show protective behavior during the challenge

Sign in as the device owner, open Guardian Shield, and attempt a connection to `exfiltration.attacker.test`. Show the simulated gateway denial. The destination is only classified in the local simulator; no external socket is opened.

### 2:05–2:20 — Finalize orphan verification

Return to the administrator after the challenge expires and finalize. Show the changed orphan state and audit history. If the countdown is still active, use the time to explain the final evidence re-check.

### 2:20–2:50 — Compare rejected and passing patch packages

As `researcher-ada`, submit `cam-b-incompatible-malicious.json` and show its failed synthetic safety checks. Submit `cam-b-community-fix-2.0.9.json` for the same verified orphan and show the passing checks. Uploaded package code is never executed.

### 2:50–3:20 — Reach reviewer quorum

As `reviewer-ada` and `reviewer-linus`, approve the passing patch. Show that a failed patch cannot enter the approval path and one vote is not enough.

### 3:20–3:50 — Release the exact signed bytes

As administrator, sign the stored package from `backend/`:

```bash
set -a && source ../.env && set +a
python -m app.sign_patch PATCH-ID
```

Paste the printed signature into the release form. Show that release records the local-chain transaction and package hash. Never copy or display the private key.

### 3:50–4:25 — Verify the simulated recovery

Notify Guardian Shield of the released patch. Show its hash, Ed25519 signature, chain release, compatibility, remediation, and virtual post-update checks. Then repeat the suspicious-host attempt and show that the recovered device has the policy produced by the prototype.

### 4:25–5:00 — Trace the records and set expectations

Open the Blockchain Audit Explorer and Risk Analytics. Compare the firmware hash and release event with the patch record and Guardian result. Close by stating that this is a local governance and workflow prototype: no physical firmware is flashed, no external scan is performed, and local chain/MQTT identities are not production infrastructure.
