# ROBOT Attack Simulation Engine (TLS 1.2 Padding Oracle)

An end-to-end containerized proof-of-concept demonstrating the **ROBOT Attack** (*Return Of Bleichenbacher's Oracle Threat*) against TLS 1.2 legacy RSA key transport infrastructure. Built entirely in Go using parallel worker synchronization.

---

## 🛠️ System Architecture

The simulation deploys a multi-node microservice environment orchestrated via Docker Compose:

[ Victim Client ] ───( Authenticated Traffic )───► [ Vulnerable TLS Server ]
       │                                                    ▲
       ▼ (Intercepts Handshake & Data)                      │
[ Attacker Sniffer ] ───( Automated Probing Loop )──────────┘

*   **Server Component:** Exposes a vulnerable TLS 1.2 endpoint enforcing RSA key transport primitives acting as a "Strong Oracle."
*   **Victim Component:** Simulates a realistic live user journey (Login $\rightarrow$ View Products $\rightarrow$ Submit Payment).
*   **Attacker Engine:** Performs passive session interception and launches the active, multi-threaded range-narrowing convergence loop.

---

## 🚀 Quick Start

### Prerequisites
*   Docker & Docker Compose
*   Go 1.21+ (for local development)

### 1. Spin Up the Environment
Clone the repository and launch the containerized ecosystem:
```bash
git clone [https://github.com/your-username/robot-tls-padding-oracle.git](https://github.com/your-username/robot-tls-padding-oracle.git)
cd robot-tls-padding-oracle
docker-compose up --build
