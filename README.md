# CipherGuard

CipherGuard is a comprehensive cybersecurity research platform and password analysis dashboard. It provides a visual and interactive way to understand password security, hashing algorithms, and vulnerability against various simulated attacks.

The project is split into two main components:
- **FastAPI Backend**: A robust API for hashing passwords, running simulated attacks, and calculating security scores.
- **React Frontend**: A modern, high-fidelity dashboard built with Vite, Tailwind CSS, and Recharts to visualize security metrics, breach simulations, and hashing performance.

## Features

### 🔐 Phase 2: Hashing Engine
- **Multiple Algorithms**: Supports `plaintext`, `MD5`, `SHA-1`, `SHA-256`, `Salted-SHA-256`, `bcrypt`, and `Argon2id`.
- **Strength Analysis**: Evaluates password complexity (entropy, length, character sets).
- **Dataset Generation**: Tools to generate large batches of hashed passwords for testing.

### ⚔️ Phase 3: Attack Simulation
- **Attack Vectors**: Simulates Dictionary, Brute Force, Rainbow Table, and Hybrid attacks.
- **Security Score Engine**: Calculates a 0-100 security score based on password strength and hashing algorithm resilience.
- **Breach Analysis**: Logs attack runs, calculates crack times, and identifies vulnerabilities.

### 📊 Interactive Dashboard
- **Immersive UI**: Dark-mode optimized, responsive layout with glassmorphism effects and modern typography.
- **Real-time Metrics**: Visualizes attack success rates, crack times, and algorithm distribution using Recharts.
- **Interactive Tools**: Test individual passwords, run attack simulations, and view detailed security scorecards.

## Technology Stack

**Backend**
- Python 3.10+
- FastAPI & Uvicorn
- SQLAlchemy & SQLite
- Passlib, bcrypt, argon2-cffi
- Pydantic

**Frontend**
- React 19 (Vite)
- Tailwind CSS
- Zustand (State Management)
- Recharts (Data Visualization)
- Framer Motion (Animations)
- Lucide React (Icons)

## Project Structure

```text
cipherguard/
├── backend/                # FastAPI Application
│   ├── app.py              # Main application entry point
│   ├── database.py         # SQLAlchemy configuration
│   ├── attacks/            # Attack simulation modules
│   ├── hashers/            # Hashing algorithm implementations
│   ├── score_engine/       # Security scoring logic
│   ├── routes/             # API endpoints
│   ├── models/             # Database models
│   ├── schemas/            # Pydantic validation schemas
│   └── requirements.txt    # Python dependencies
│
├── frontend/               # React Dashboard
│   ├── src/
│   │   ├── components/     # Reusable UI components
│   │   ├── pages/          # Dashboard views
│   │   ├── store/          # Zustand state management
│   │   └── App.jsx         # Main React component
│   ├── package.json        # Node.js dependencies
│   ├── tailwind.config.js  # Tailwind styling rules
│   └── vite.config.js      # Vite configuration
│
└── cipherguard.db          # SQLite Database
```

## Setup & Installation

### Prerequisites
- Node.js 18+ and npm
- Python 3.10+

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

## Running the Application

### Start the Backend Server
Run this from the **root of the project** (`cipherguard` directory):
```bash
# On Windows
.\backend\venv\Scripts\activate
uvicorn backend.app:app --reload --port 8000

# On Linux/macOS
source backend/venv/bin/activate
uvicorn backend.app:app --reload --port 8000
```
The API documentation will be available at [http://localhost:8000/docs](http://localhost:8000/docs).

### Start the Frontend Development Server
Open a new terminal window:
```bash
cd frontend
npm run dev
```
The dashboard will be available at [http://localhost:5173](http://localhost:5173).

## API Endpoints Overview

- `GET /` - API Health and capabilities.
- `POST /api/v1/hash` - Hash a password using a specific algorithm.
- `POST /api/v1/analyze` - Analyze password strength and entropy.
- `POST /api/v1/run-attack` - Execute an attack simulation against a hashed password.
- `GET /api/v1/attack-results` - Retrieve historical attack logs.
- `GET /api/v1/security-score` - Get a detailed scorecard for a specific algorithm and complexity.

## License

This project is licensed under the MIT License.
