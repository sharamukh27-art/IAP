# IoT AFTERLIFE PROTOCOL — Local Installation Guide

This guide installs the software-only prototype for local development. It does not configure physical IoT equipment or a production identity provider.

## Prerequisites

- Python 3.9 or newer
- Node.js 22.13 or newer and npm
- MongoDB 7 or newer, locally or through Docker Compose
- Docker Compose v2 for the bundled MongoDB and Mosquitto services, or compatible local services
- A shell with the commands below (Bash examples are shown)

The API and development services are intended to bind to loopback addresses. Do not expose the anonymous Mosquitto broker or unlocked Hardhat accounts to an untrusted network.

## Configure local credentials

From the project root:

```bash
cp .env.example .env
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Set the generated value as `AUTH_SECRET_KEY` in `.env`, and replace `AUTH_BOOTSTRAP_ADMIN_PASSWORD` with a unique password of at least 12 characters. The example placeholders are intentionally rejected by the API. Keep `.env`, the generated community private signing key, and local deployment metadata out of version control.

## Install dependencies

```bash
cd chain
npm ci
npm run compile
npm test

cd ../backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

cd ../frontend
npm ci
```

## Start the application

Use separate terminals, all opened at the project root unless a step changes directory.

1. Start the database and local-only MQTT broker:

   ```bash
   docker compose up -d mongo mosquitto
   ```

2. Start the local Hardhat node and leave it running:

   ```bash
   cd chain
   npm run node
   ```

3. In a second chain terminal, compile/deploy the contract:

   ```bash
   cd chain
   npm run deploy:local
   ```

   This creates local deployment metadata and a backend-only Ed25519 key if one does not already exist. The demo assigns one unlocked local manufacturer account to its fictional manufacturer names; a production system would need distinct verified organization accounts.

4. Start the API and seed its fictional device records:

   ```bash
   cd backend
   source .venv/bin/activate
   set -a
   source ../.env
   set +a
   python -m app.seed
   uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

5. Start the web client:

   ```bash
   cd frontend
   npm run dev -- --host 127.0.0.1
   ```

Open <http://127.0.0.1:5173>, then sign in with `AUTH_BOOTSTRAP_ADMIN_USERNAME` and the password from `.env`. The API is at <http://127.0.0.1:8000>; health check: <http://127.0.0.1:8000/health>; API schema: <http://127.0.0.1:8000/docs>.

## Provision workflow accounts

Use **Settings & Users** while signed in as the bootstrap administrator. Provision distinct manufacturer, security researcher, independent reviewer, and device-owner accounts with only the required scopes. The local contract assigns three reviewer addresses and requires two votes; the demo reviewer IDs are `reviewer-ada`, `reviewer-linus`, and `reviewer-grace`.

The token remains in browser `sessionStorage` and is removed when the session expires or the user signs out.

## Verify the installation

In the project directories, run:

```bash
cd backend
source .venv/bin/activate
python -m pytest -q

cd ../chain
npm test

cd ../frontend
npm run build
```

Check `/health` for the API, `/api/blockchain/status` while authenticated for local-chain availability, and the Guardian page for MQTT status. MongoDB, Hardhat, Mosquitto, and the UI/API processes must all be running for the full interactive workflow.

## Stop and reset

- Stop the API, UI, and Hardhat node with `Ctrl-C` in their respective terminals.
- Stop the Compose services with `docker compose down`; persisted MongoDB data remains in its named volume.
- A fresh local chain has no prior contract state. Start a new node and run `npm run deploy:local` again before the API.
- `python -m app.seed` upserts the sample devices; it does not erase user accounts, workflow history, or existing MongoDB collections.
- Do not delete the MongoDB volume or generated key unless you intend to reset that local data and have confirmed the exact target.

The backend tests use Mongomock for isolation. A passing test run does not replace a smoke test against a separately running MongoDB service.
