# 🚨 0xNeural V2: Autonomous Smart Contract Trawler

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-green)
![FastAPI](https://img.shields.io/badge/FastAPI-v0.100%2B-009688)
![Torch](https://img.shields.io/badge/PyTorch-v2.0%2B-EE4C2C)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

**0xNeural V2** is a professional-grade, autonomous smart contract security auditing pipeline. It combines local **Retrieval-Augmented Generation (RAG)** using high-dimensional vector embeddings with advanced LLM reasoning to identify High and Critical severity logic flaws in real-time.

By bridging the gap between historical exploit data and real-time on-chain activity, 0xNeural V2 acts as an automated "hunter" that scouts the Ethereum network for vulnerable targets, performs automated OSINT, and generates structured security reports.

---

## 🚀 Key Features

- **🧠 Local Vector DB (The Librarian):** Uses `SentenceTransformers` and `PyTorch` to perform sub-millisecond similarity searches against a curated database of 50,000+ historical hacks and audit findings.
- **⚡ Non-Blocking AI Analyst:** A high-performance FastAPI backend that leverages Google's **Gemini 2.5 Flash** to perform deep logical analysis with Chain-of-Thought reasoning.
- **🦇 Autonomous Hunting:** A multi-source trawler that pipes live contract deployments from **Alchemy (WebSockets)**, **Blockscout (API)**, and **Etherscan** directly into the auditing engine.
- **🕵️ Automated OSINT:** Automatically performs identity dossiers on contract creators, resolving ENS names and searching for related public GitHub repositories to filter for high-value bug bounty targets.
- **🚨 Real-time Alerting:** Structured Discord notifications featuring vulnerability summaries, exploit paths, and remediation steps delivered instantly upon detection.
- **🛡️ OPSEC Anonymization:** Automatically scrubs protocol-specific identifiers before cloud analysis to maintain operational security.
- **♻️ Smart Caching:** SHA256-based result caching to minimize API costs and maximize throughput.

---

## 📋 Prerequisites

### Software Requirements
- **Python 3.10+** (Recommended: 3.11 or 3.12)
- **CUDA-compatible GPU** (Optional, for faster vector search. Defaults to CPU.)
- **Operating System:** Windows, Linux, or macOS.

### System Dependencies
- `PyTorch v2.0+`
- `FastAPI` & `Uvicorn`
- `Sentence-Transformers`
- `Google Generative AI SDK`

### API Keys (Required in `.env`)
- **GEMINI_API_KEY:** From [Google AI Studio](https://aistudio.google.com/)
- **ETHERSCAN_API_KEY:** From [Etherscan.io](https://etherscan.io/)
- **ALCHEMY_WSS_URL:** From [Alchemy.com](https://www.alchemy.com/)
- **DISCORD_WEBHOOK_URL:** For real-time alerts.
- **GITHUB_TOKEN:** (Optional) For automated OSINT repo searching.

---

## 🛠️ Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/your-repo/0xNeural_V2.git
   cd 0xNeural_V2
   ```

2. **Initialize Environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables:**
   Create a `.env` file in the root directory:
   ```env
   GEMINI_API_KEY=your_key_here
   ETHERSCAN_API_KEY=your_key_here
   ALCHEMY_WSS_URL=wss://eth-mainnet.g.alchemy.com/v2/your_key
   DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
   GITHUB_TOKEN=your_token_here
   ```

4. **Initialize Local Brain:**
   If you have a collection of PDFs/JSONs, drop them in `audit_reports/` and run:
   ```bash
   python scripts/update_vacuum.py
   ```

---

## 📖 Usage Guide

The system operates as a distributed pipeline. You should run these in separate terminals:

### 1. Start the Command Center (Engine)
The engine must be running to handle scan requests.
```bash
# From the project root
python engine/app.py
```
*The engine listens at `http://127.0.0.1:8000/scan`.*

### 2. Launch a Feeder (Live Data Source)
Choose one or more sources to pipe targets into the queue.
```bash
# Monitor live deployments via Alchemy WebSockets
python feeders/alchemy_feeder.py

# Monitor recently verified contracts via Blockscout
python feeders/blockscout_feeder.py
```

### 3. Activate the Hunter
The hunter watches `target_queue.txt` and orchestrates the auditing process.
```bash
python engine/autonomous_hunter.py queue
```

### Manual Usage
You can scan a specific address directly:
```bash
python engine/autonomous_hunter.py 0x123...abc
```
Or force a scan on code that would normally be filtered out:
```bash
python engine/autonomous_hunter.py 0x123...abc --force
```

---

## 📂 Project Structure

```text
0xNeural_V2/
├── data/               # Vector DB matrices and metadata
├── engine/             # Core logic (FastAPI, Hunter, OSINT Utils)
│   ├── app.py          # RAG + LLM Backend
│   ├── autonomous_hunter.py # Orchestrator
│   └── hunter_utils.py # OSINT & API Helpers
├── feeders/            # Real-time data source scripts
├── reports/            # Generated Markdown audit reports
├── scripts/            # Database maintenance & ingestion tools
├── logs/               # Operational logs
├── .env                # Secrets (Gitignored)
├── requirements.txt    # Dependencies
└── target_queue.txt    # Shared queue for feeders/hunter
```

---

## ⚙️ Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `LOCAL_API_URL` | Engine URL | `http://127.0.0.1:8000/scan` |
| `CACHE_DIR` | Location of scan cache | `cache/` |
| `RETRY_INTERVAL` | Wait time after rate limits | `300s` |
| `MAX_RETRIES` | Max attempts per target | `12` |

---

## 🧪 Testing & Verification

- **Unit Tests:** Ensure core OSINT functions resolve correctly in `hunter_utils.py`.
- **Integration:** Run `app.py` and use `curl` to test the `/scan` endpoint.
- **Connectivity:** Run `alchemy_feeder.py` to verify WebSocket stability.

---

## 🚀 Deployment

- **Staging:** Run locally on a dedicated machine with a stable internet connection.
- **Production:** Recommended deployment on a VPS (Ubuntu 22.04+) with `screen` or `pm2` for process management.
- **Resource Note:** Ensure the machine has at least 8GB RAM to handle the vector database and LLM model responses.

---

## 🛠️ Troubleshooting

- **`Brain files not found`:** Run `scripts/update_vacuum.py` to build the initial database.
- **`Connection Refused`:** Ensure `app.py` is running and accessible on port 8000.
- **`Rate Limit Hit`:** The Hunter will automatically move targets to the `waiting_room.json` and retry every 5 minutes.
- **`Blocked by Safety Filters`:** Gemini may block responses for highly aggressive exploit code. These are logged and skipped.

---

## 📄 License & Attribution

This project is licensed under the **MIT License**.
- **Vector Search:** Powered by [BAAI/bge-small-en-v1.5](https://huggingface.co/BAAI/bge-small-en-v1.5).
- **LLM Reasoning:** Powered by [Google Gemini](https://ai.google.dev/).

---

## 🤝 Contributing

1. **Fork** the repo and create your branch.
2. **Coding Standards:** Follow PEP 8 for Python logic.
3. **PR Process:** Ensure all feeders are tested before submission.
4. **Issue Tracking:** Use the GitHub issue tracker for bugs and feature requests.

---

**Maintainer:** Emmanuel Ogezi
