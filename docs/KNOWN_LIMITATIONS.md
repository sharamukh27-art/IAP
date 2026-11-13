# IoT AFTERLIFE PROTOCOL — Known Limitations

This document distinguishes prototype design decisions from production gaps. The application is a software prototype for academic and demonstration purposes only.

## Simulation boundary

Every device, manufacturer, vulnerability, firmware payload, and reviewer identity is fictional. No physical IoT hardware is scanned, controlled, or updated. No real manufacturer API is probed. No real vulnerability database is queried. No live firmware binary is transferred to any device. The blockchain is a local Hardhat development node with unlocked test accounts.

## Authentication and authorization

| # | Limitation |
|---|---|
| A1 | The token format is a custom HMAC-SHA256 scheme, not standard JWT. It is not interoperable with standard JWT middleware, OAuth 2.0 flows, or external identity providers. |
| A2 | No rate limiting or account lockout on the login endpoint. A local development prototype does not enforce brute-force protection. |
| A3 | The bootstrap admin password must be set via environment variable before first run; there is no secure out-of-band initial enrollment flow. |
| A4 | Tokens are stored in browser `sessionStorage`. They are accessible to same-origin JavaScript (not HttpOnly). For a production deployment, tokens would need to be in HttpOnly cookies or a backend-for-frontend pattern. |
| A5 | No multi-factor authentication. |

## Key management

| # | Limitation |
|---|---|
| K1 | The community Ed25519 private key is stored as an unencrypted PEM file on disk. A production system would use an HSM, Vault, or encrypted key store. |
| K2 | Key rotation is not implemented. If the private key is compromised, all released patches signed with that key would need to be revoked manually. |
| K3 | The blockchain actors are unlocked Hardhat development accounts. They have no corresponding private key management in Python. These accounts must not be exposed to any real network. |

## Patch safety laboratory

| # | Limitation |
|---|---|
| P1 | The malware scan uses a fixed list of literal keyword strings. Obfuscation (string concatenation, base64 encoding, Unicode normalization) would bypass detection. The scan is designed for a bounded, structured JSON format where the payload is metadata, not executable code. |
| P2 | The safety checks are entirely deterministic and synthetic. They do not execute uploaded content in a sandbox, run a real antivirus, or perform dynamic analysis. |
| P3 | The rollback field is checked for presence and structure only. Its content is not evaluated for safety. |

## Orphan detection

| # | Limitation |
|---|---|
| O1 | All six evidence signals are simulated. No real manufacturer API, certificate authority, or DNS record is queried. The simulation engine injects evidence signals explicitly; it does not monitor real infrastructure. |
| O2 | The orphan challenge period is 60 seconds for demonstration. A production deployment would require a minimum period measured in days or weeks. |
| O3 | Reviewer identities are authenticated platform accounts but not independently verified real-world organizations. |

## Blockchain

| # | Limitation |
|---|---|
| B1 | The governance contract runs on a local Hardhat node. Contract state is not persistent across node restarts. After restarting the node, the deployment script must be rerun. |
| B2 | The contract uses unlocked development accounts and no gas pricing. It is not suitable for a public testnet or mainnet. |
| B3 | The contract maps manufacturer names to a shared development account, not distinct real organizations. A production deployment would require verified organizational accounts. |
| B4 | The contract has no on-chain governance for key rotation or protocol upgrades. |

## Guardian and MQTT

| # | Limitation |
|---|---|
| G1 | The MQTT broker allows anonymous connections. No TLS is configured. The broker is now bound to loopback only, but authentication and transport encryption are not implemented. |
| G2 | The virtual Guardian agents and gateway run in the same Python process as the FastAPI server via background threads. In production, these would be separate services. |
| G3 | The gateway decision engine uses a small, fixed list of suspicious-host keywords. It does not perform DNS-based reputation checks, TLS certificate inspection, or traffic payload analysis. |
| G4 | The gateway never opens a real socket. All "network decisions" are simulated hostname classification. |

## Frontend

| # | Limitation |
|---|---|
| F1 | No Content Security Policy (CSP) header is configured for the production build. |
| F2 | The Vite development server proxy (`/api` → `localhost:8000`) is not suitable for production. A production deployment would need a reverse proxy (nginx, Caddy). |
| F3 | The browser UI does not support role switching without signing out. |
| F4 | No offline or service-worker support. All dashboard values require a live API connection. |

## Production readiness statement

This application is **not production-ready** and is **not independently security-certified**. It is a local development prototype that demonstrates a governance lifecycle concept. The following must be addressed before any production deployment:

- Replace the custom token format with a standard identity provider (e.g. OAuth 2.0 / OIDC).
- Move private keys to an HSM or encrypted key management service.
- Replace the anonymous MQTT broker with a broker using TLS and certificate-based authentication.
- Replace Hardhat local accounts with verified organizational accounts on a permissioned chain.
- Add rate limiting, audit logging to an append-only store, and intrusion detection.
- Conduct an independent security review and penetration test.
- Replace literal malware keyword scanning with a sandboxed execution environment.
- Use HttpOnly cookies or a BFF pattern for token storage.
