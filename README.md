# ROBOT Attack Simulation Engine (TLS 1.2 Padding Oracle)

An end-to-end containerized proof-of-concept demonstrating the **ROBOT Attack** (*Return Of Bleichenbacher's Oracle Threat*) against TLS 1.2 legacy RSA key transport infrastructure. Built entirely in Go using parallel worker synchronization.

> **Educational use only.** Everything runs inside a self-contained Docker network against a deliberately vulnerable lab server. It is a teaching simulation of a publicly documented (CVE-2017-13099) weakness, not a tool aimed at real systems.

---

## 🛠️ System Architecture

The simulation deploys a multi-node microservice environment orchestrated via Docker Compose:

```
[ Victim Client ] ───( Authenticated Traffic )───► [ Vulnerable TLS Server ]
       │                                                    ▲
       ▼ (Intercepts Handshake & Data)                      │
[ Attacker Sniffer ] ───( Automated Probing Loop )──────────┘
```

*   **Server Component:** Exposes a vulnerable TLS 1.2 endpoint enforcing RSA key transport primitives, acting as a "Strong Oracle."
*   **Victim Component:** Simulates a realistic live user journey (Login → View Products → Submit Payment).
*   **Attacker Engine:** Performs passive session interception, then launches the active, multi-threaded range-narrowing convergence loop.

---

## 🔬 How It Works

1. **Intercept** — the attacker sniffs the TLS handshake and application data between the victim and the server, extracting the `ClientKeyExchange` ciphertext and the client/server handshake randoms.
2. **Probe** — it sends crafted RSA ciphertexts to the server and classifies each response as valid/invalid PKCS#1 padding, using the server as a padding oracle (`ATTACK_CONCURRENCY` parallel probes).
3. **Converge** — the classic Bleichenbacher interval-narrowing loop (goroutines + `atomic` query counting) recovers the Pre-Master Secret from the intercepted ciphertext.
4. **Derive & Decrypt** — the recovered PMS drives the TLS key schedule (Master Secret → session keys), and the captured AES-CBC application data is decrypted and written to the session log.

---

## 🚀 Quick Start

### Prerequisites
*   Docker & Docker Compose
*   Go 1.21+ (only for local development outside containers)

### 1. Spin Up the Environment
Clone the repository and launch the containerized ecosystem:
```bash
git clone https://github.com/BenyHanonove/robot-tls-padding-oracle.git
cd robot-tls-padding-oracle
docker-compose up --build
```

The three services start in order: the vulnerable server, the attacker engine, then the victim (which waits 10s before generating traffic).

### 2. Watch the Attack
The attacker logs its progress to stdout. On success it prints the recovered secrets and the decrypted application data:

```
--- ATTACK CONVERGED ---
Total Oracle Queries: <n>
Total Time to Convergence: <duration>
Target Key Size: RSA 2048-bit (Laboratory Optimized)

--- RECOVERED SECRETS ---
Recovered Pre-Master Secret (PMS): <hex>
Derived Master Secret:             <hex>
Derived AES Key (Client):          <hex>

--- DECRYPTED APPLICATION DATA ---
[victim -> server] Decrypted: <recovered plaintext>
```

Full encrypted and decrypted traffic logs are saved under `attacker/captures/`.

---

## ⚙️ Configuration

Each service reads its settings from a local `.env` file (`server/`, `attacker/`, `victim/`). Key attacker knobs:

| Variable | Purpose |
|---|---|
| `ATTACK_CONCURRENCY` | Number of parallel oracle probes |
| `ORACLE_TIMEOUT_MS` | Per-request timeout waiting for the server |
| `TARGET_HOST` / `TARGET_PORT` | Vulnerable server address inside the Docker network |

---

## 🧰 Tech Stack

Go 1.21 · `math/big` for RSA arithmetic · goroutines + `sync/atomic` for parallel convergence · standard-library `crypto` for the TLS key schedule and AES-CBC · Docker Compose for the isolated 3-node lab network.
