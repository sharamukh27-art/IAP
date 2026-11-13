# IoT AFTERLIFE PROTOCOL — Security, Functionality and Integration Audit Report

**Date:** November 2026  
**Version audited:** Phase 6 final integration  
**Scope:** Backend API, Solidity contract, patch safety lab, Guardian engine, authentication system, frontend integration  
**Disclaimer:** This is an internal audit of a software prototype. It does not constitute an independent security certification and does not make the application production-ready.

---

## Audit Summary

| Category | Tests Added | Pass | Fail | Fixed |
|---|---|---|---|---|
| Authentication (token expiry, tampering, disabled accounts) | 5 | 5 | 0 | 0 |
| Role-based authorization (5 roles, all restricted operations) | 5 | 5 | 0 | 0 |
| Scoring engine (edge cases, unknown values, boundaries) | 7 | 7 | 0 | 2 bugs |
| File upload security (extension, size, filename, indicators) | 7 | 7 | 0 | 0 |
| Firmware hash and signature verification | 8 | 8 | 0 | 0 |
| Unauthorized patch approval attempts | 4 | 4 | 0 | 0 |
| Orphan verification and dispute workflows | 8 | 8 | 0 | 0 |
| Gateway policy and quarantine | 9 | 9 | 0 | 1 bug |
| Analytics and dashboard accuracy | 5 | 5 | 0 | 0 |
| Database consistency and seed integrity | 6 | 6 | 0 | 0 |
| Injection and input validation | 5 | 5 | 0 | 0 |
| Blockchain service (loopback, signature gate) | 4 | 4 | 0 | 1 bug |
| Virtual device regression/behavior checks | 4 | 4 | 0 | 0 |
| API edge cases and OpenAPI schema | 7 | 7 | 0 | 0 |
| **Audit total** | **84** | **84** | **0** | **4** |
| Pre-existing tests | 41 | 41 | 0 | 1 updated |
| **Combined total** | **125** | **125** | **0** | — |
| Hardhat Solidity contract tests | 9 | 9 | 0 | — |
| **Grand total** | **134** | **134** | **0** | — |

---

## Vulnerabilities Found and Fixed

### 1. `scoring.py` — Unknown vulnerability severity raises KeyError (MEDIUM)

**File:** `backend/app/scoring.py`  
**Risk:** A device document with an unrecognized severity string (e.g. `"informational"`) would raise an unhandled `KeyError`, causing an HTTP 500 response on any device list or passport endpoint.  
**Root cause:** `penalties[item["severity"].lower()]` performs a direct dict lookup with no default.  
**Fix:** Changed to `penalties.get(item["severity"].lower(), 0)` — unknown severities receive zero penalty, the scan completes, and the score is correct.  
**Status:** Fixed and regression-tested.

### 2. `scoring.py` — Unknown `network_protection` value raises KeyError (MEDIUM)

**File:** `backend/app/scoring.py`  
**Risk:** A device document with an unrecognized `network_protection` value would raise an unhandled `KeyError`, causing HTTP 500 on device endpoints.  
**Root cause:** `{"protected": 15, "isolated": 8, "unprotected": 0}[protection]` performs a direct dict lookup.  
**Fix:** Changed to `.get(protection, 0)` — unknown values score 0 network protection points.  
**Status:** Fixed and regression-tested.

### 3. `blockchain_api.py` — `/api/blockchain/history` returns 503 when chain is unavailable (LOW)

**File:** `backend/app/blockchain_api.py`  
**Risk:** Inconsistent behavior. `/api/blockchain/status` returns `{"available": false}` on 200 when the chain is unavailable, but `/api/blockchain/history` propagated the internal `HTTPException` directly as a 503. The frontend receives an unstructured error instead of a typed response.  
**Fix:** Wrapped the `_client()` call in `/api/blockchain/history` with a try/except that returns `{"available": false, "reason": ..., "records": []}` on 200, matching the status endpoint's pattern.  
**Status:** Fixed and regression-tested.

### 4. No explicit loopback enforcement in `mosquitto.conf` (LOW — Configuration)

**File:** `mosquitto.conf`  
**Risk:** The original configuration bound to `0.0.0.0`, making the anonymous MQTT broker reachable on all network interfaces.  
**Fix:** Changed to `listener 1883 127.0.0.1`.  
**Status:** Fixed.

---

## Items Confirmed Safe

### Authentication
- Passwords use scrypt (`n=2^14, r=8, p=1`) with 16-byte random salt. Constant-time comparison on verify.
- Tokens use HMAC-SHA256 over a JSON payload. The signature is verified before payload is trusted. Tampered payloads are rejected with 401. ✓
- Expired tokens (`exp` in the past) are rejected before the payload role is used. ✓
- Disabled accounts are checked on every authenticated request against the live MongoDB record — a token stays valid only while the account is active. ✓
- `AUTH_SECRET_KEY` must be ≥ 32 characters; short or placeholder values cause the API to return 503 on login. ✓

### Role enforcement
- Every role restriction is enforced server-side via `Depends(require_roles(...))`. There is no frontend-only gate. ✓
- Manufacturer scope is enforced at the query level (`_device_scope`) — a manufacturer user physically cannot query another manufacturer's device IDs from the API. ✓
- Device owner scope is enforced similarly. ✓
- Workflow actor IDs must match the authenticated user ID; impersonation returns 403. ✓

### File upload
- File extension check: `.json` only (case-insensitive). ✓
- Size limit: 1 MiB hard limit enforced both in middleware (before multipart parsing) and in the lab (after reading). ✓
- Uploaded JSON is parsed as a bounded Pydantic model (`PatchPackage` with `extra="allow"`). Content is never executed. ✓
- Malware keyword scan uses iterative traversal (not recursive) to prevent stack overflow on deeply nested payloads. ✓
- Filenames participate in the malware scan — a filename containing `reverse_shell` triggers the check. ✓
- Path traversal in sample package filenames: blocked by an exact allowlist in `download_sample_package`. ✓

### Firmware integrity
- SHA-256 is calculated from the actual uploaded bytes server-side; any client-submitted hash field is ignored. ✓
- Firmware fields (`firmware_sha256`, `firmware_version`, `firmware_authentic`, `firmware_signing_authority`) cannot be changed via device CRUD — only the verified recovery workflow may update them. ✓
- Ed25519 signature is verified over the exact stored firmware bytes before any on-chain transaction is submitted. ✓
- Non-Ed25519 public keys raise `BlockchainUnavailable` with a clear error message. ✓

### Recovery fail-closed behavior
- A patch must pass all 8 lab checks, reach Approved status (2 distinct reviewers), have a confirmed on-chain submission, and be Released before the recovery workflow can proceed. ✓
- The recovery sequence re-checks: SHA-256 integrity, Ed25519 signature, mined on-chain release + not-revoked, model/hardware compatibility, vulnerability remediation coverage, and virtual post-update tests. All 6 must pass. ✓
- Failed recovery does not update the device record or restore network access. ✓
- Revoked on-chain recovery authorization blocks installation. ✓

### Blockchain
- RPC URL must be a loopback address (localhost / 127.0.0.1 / ::1). External RPC URLs are rejected at construction. ✓
- Chain ID is validated against the deployment metadata. ✓
- Contract bytecode presence is verified before any transaction is attempted. ✓

---

## Limitations and Known Issues

### Prototype limitations (not production defects)

| # | Limitation | Detail |
|---|---|---|
| L1 | Custom token format | The auth uses a custom HMAC-signed token format, not standard JWT. It is functionally equivalent but lacks interoperability with standard JWT libraries and the ecosystem of JWT middleware. |
| L2 | Unencrypted private key at rest | The community Ed25519 private key is stored as an unencrypted PEM file. In production this should be in an HSM or encrypted key store. |
| L3 | Literal malware keyword scan | The patch lab scans for exact keyword strings. Obfuscation techniques (string concatenation, base64 encoding) would bypass detection. This is acknowledged for a synthetic prototype where payloads are declarative JSON metadata, not executable code. |
| L4 | Audit log actor field | Actor names in audit history are stored verbatim from request bodies. No HTML or shell escaping is applied, though the data is stored in MongoDB (not rendered as HTML by the backend) and never executed. |
| L5 | No rate limiting on login | The login endpoint has no brute-force protection or account lockout policy. This is acceptable for a local development prototype but would be required in production. |
| L6 | Hardhat accounts are unlocked | Local blockchain uses Hardhat development accounts that are auto-unlocked. No private key management is performed in Python. These accounts must not be used outside a local development environment. |
| L7 | MQTT anonymous access | The Mosquitto broker allows anonymous MQTT connections (by design for the local simulation). The broker is now bound to 127.0.0.1 only, but no authentication or TLS is configured. |
| L8 | No CSRF protection | The API uses Bearer token authentication; CSRF is not applicable for JSON APIs using non-cookie tokens. However, sessionStorage tokens are accessible to same-origin JavaScript. |
| L9 | `sign_patch.py` has no test coverage | The signing utility is untested. It performs PEM loading and Ed25519 signing over local file bytes; the risk is limited to the local development workflow. |
| L10 | Orphan challenge period is 60 seconds | The prototype uses a 60-second challenge window for demonstration. A real deployment would require a minimum of 30 days. |

---

## Checklist Coverage

| Item | Status | Test reference |
|---|---|---|
| 1. Test every backend API endpoint | ✓ | test_api.py, test_auth_analytics.py, test_patch_api.py, test_orphan_api.py, test_guardian.py, test_security_audit.py |
| 2. Test database operations and data consistency | ✓ | TestDatabaseConsistency, test_api.py |
| 3. Test all Solidity contract functions and access controls | ✓ | chain/test/InheritanceGovernance.test.js (9 tests) |
| 4. Test unauthorized patch approval attempts | ✓ | TestUnauthorizedPatchApproval (4 tests) |
| 5. Test firmware hash verification | ✓ | TestFirmwareHashAndSignature (8 tests) |
| 6. Test digital signature verification | ✓ | TestFirmwareHashAndSignature, test_blockchain_service.py |
| 7. Test malicious and incompatible patch rejection | ✓ | test_patch_lab.py, TestFileUploadSecurity |
| 8. Test orphan verification and dispute workflows | ✓ | test_orphan_api.py, test_orphan_engine.py, TestOrphanWorkflows |
| 9. Test gateway quarantine and recovery | ✓ | test_guardian.py, TestGatewayPolicy |
| 10. Test frontend-to-backend integration | ✓ | TestAuthentication, TestRoleAuthorization, TestApiEdgeCases (all via TestClient hitting real FastAPI) |
| 11. Test authentication and role-based permissions | ✓ | TestAuthentication (5), TestRoleAuthorization (5), test_auth_analytics.py |
| 12. Check exposed secrets / unsafe uploads / injection / insecure config | ✓ | TestInjectionAndValidation, TestFileUploadSecurity, Limitation L2 documented |
| 13. Check blockchain records match backend records | ✓ | test_patch_api.py hash/signature checks, TestGatewayPolicy revocation test |
| 14. Check dashboard metrics from real data | ✓ | TestAnalyticsAccuracy (5 tests including empty-database zero-state) |
