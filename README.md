# CipherGuard 🛡️

CipherGuard is an advanced, full-stack cybersecurity research platform and password analysis dashboard. Designed to visualize cryptographic vulnerabilities in real-time, the platform demonstrates how different hashing algorithms fare against simulated cracking attacks.

This project was built to illustrate why "fast" algorithms (like MD5 or SHA-256) are dangerous for password storage, and why computationally expensive, salted algorithms (like bcrypt and Argon2id) are the industry standard.

---

## 🚀 Executive Summary (For Interviewers)

CipherGuard is not just a hashing tool; it is a **multi-threaded attack simulation engine** with a high-fidelity frontend. 
Key technical achievements include:
*   **Asynchronous Streaming (SSE)**: Uses Server-Sent Events (SSE) to stream live attack data from a background Python thread to the React UI in real-time without blocking the main event loop.
*   **In-Memory Secure Sessions**: Features a "Custom Password Attack" mode where plaintext passwords are hashed in memory, stored in a thread-safe global session, and garbage-collected immediately. Plaintext never touches a disk or database.
*   **Deterministic Security Scoring**: Features a custom math engine that bounds algorithms by their cryptographic properties (floor/ceiling) and adjusts their score dynamically based on benchmark simulation speed and crack rates.
*   **Modern React Architecture**: Utilizes Vite, Tailwind CSS, Recharts, and Zustand for highly responsive state management and real-time data visualization.

---

## 💡 Core Features

### 1. The Hashing Engine
- **Supported Algorithms**: `plaintext`, `MD5`, `SHA-1`, `SHA-256`, `Salted-SHA-256`, `bcrypt`, and `Argon2id`.
- **Entropy Analysis**: Calculates mathematical unpredictability ($E = L \times \log_2(C)$) based on character set depth.
- **Dataset Generation**: Generates thousands of mock password records using mutated wordlists to provide realistic attack surfaces.

### 2. The Attack Simulation Engine
Simulates real-world password cracking techniques:
- **Dictionary Attack**: Linear $O(N)$ lookup against a targeted wordlist.
- **Brute Force Attack**: Exhaustive permutation generation using `itertools`.
- **Hybrid Attack**: Wordlist combinations mutated with common patterns (e.g., Leetspeak, appended numbers).
- **Rainbow Table Attack**: Precomputed $O(1)$ lookup tables, specifically designed to demonstrate how dynamic salts (bcrypt/Argon2id) instantly defeat this attack vector.

### 3. The Live Attack Dashboard (SSE)
- Watch attacks unfold in real-time.
- View live metrics including **Attempts per Second**, **Crack Rate**, and **Estimated GPU Time** (estimating how an RTX 4090 would perform vs the algorithm).
- Supports both **Database Dataset Attacks** and isolated **Custom Password Attacks**.

---

## 🛠️ Technology Stack

**Backend (Python 3.10+)**
- **FastAPI / Uvicorn**: High-performance async API.
- **SQLAlchemy / SQLite**: Target and result persistence.
- **Passlib & argon2-cffi**: Enterprise-grade cryptographic hashing.
- **Python Threading & Queues**: Background worker threads passing events back to the FastAPI generator.

**Frontend (React 19)**
- **Vite**: Rapid build tooling.
- **Tailwind CSS**: Utility-first, dark-mode optimized styling.
- **Zustand**: Lightweight global state management.
- **Recharts**: D3-based charting for security scorecards and benchmark analytics.

---

## 🏗️ Project Structure

```text
cipherguard/
├── backend/                # FastAPI Application
│   ├── app.py              # Application entry point & CORS
│   ├── attacks/            # Dictionary, Brute Force, Hybrid, Streaming Engines
│   ├── hashers/            # Cryptographic implementations
│   ├── score_engine/       # Security scoring and math logic
│   ├── routes/             # REST and SSE API endpoints
│   ├── utils/              # GPU time estimation & Dataset generators
│   └── logs/               # JSON attack benchmark logs
│
├── frontend/               # React Dashboard
│   ├── src/
│   │   ├── components/     # Reusable UI cards and charts
│   │   ├── pages/          # Dashboard, Live Attack, Salting Visualizer
│   │   ├── services/       # API integration layers
│   │   └── store/          # Zustand stores
│   └── package.json        
```

---

## ⚙️ Setup & Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd cipherguard
```

### 2. Backend Setup
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
pip install -r requirements.txt
```

### 3. Frontend Setup
```bash
cd ../frontend
npm install
```

---

## 🏃 Running the Application

### Start the Backend Server
Run this from the **root of the project** (`cipherguard` directory):
```bash
# On Linux/macOS
source backend/venv/bin/activate
uvicorn backend.app:app --reload --port 8000

# On Windows
.\backend\venv\Scripts\activate
uvicorn backend.app:app --reload --port 8000
```
API Documentation (Swagger UI): [http://localhost:8000/docs](http://localhost:8000/docs)

### Start the Frontend Server
Open a new terminal window:
```bash
cd frontend
npm run dev
```
Dashboard: [http://localhost:5173](http://localhost:5173)

---

## 📡 Key API Endpoints

- **`POST /api/v1/hash`**: Cryptographically hash a plaintext input.
- **`POST /api/v1/run-attack`**: Execute a synchronous attack simulation and save the report.
- **`GET /api/v1/stream-attack`**: Stream Server-Sent Events (SSE) for dataset attacks.
- **`POST /api/v1/custom-stream-attack`**: Intialize a secure, in-memory attack session.
- **`GET /api/v1/custom-stream-attack/{id}/stream`**: Consume the session and stream real-time events.
- **`GET /api/v1/security-score`**: Retrieve the 0-100 algorithm benchmark scores.

---

## 📄 License
This project is licensed under the MIT License.
