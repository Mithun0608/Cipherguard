import axios from 'axios'

const BASE = 'http://127.0.0.1:8000/api/v1'

const api = axios.create({
  baseURL: BASE,
  timeout: 300_000,
  headers: { 'Content-Type': 'application/json' },
})

// ── Response interceptor ───────────────────────────────────────
api.interceptors.response.use(
  (r) => r,
  (err) => {
    const msg = err.response?.data?.detail || err.message || 'API Error'
    return Promise.reject(new Error(msg))
  }
)

// ── Hashing ───────────────────────────────────────────────────
export const hashPassword   = (data)  => api.post('/hash', data)
export const verifyPassword = (data)  => api.post('/verify', data)
export const analyzePassword= (pwd)   => api.post('/analyze', { password: pwd })
export const hashAll        = (pwd)   => api.post('/hash-all', { password: pwd })
export const getAlgorithms  = ()      => api.get('/algorithms')

// ── Dataset ───────────────────────────────────────────────────
export const generateDataset = (data) => api.post('/generate-dataset', data)

// ── Attacks ───────────────────────────────────────────────────
export const runAttack       = (data) => api.post('/run-attack', data)
export const getAttackResults= (params) => api.get('/attack-results', { params })
export const getAttackLogs   = (limit=20) => api.get('/attack-logs', { params: { limit } })

// ── Security Score ────────────────────────────────────────────
export const getSecurityScore = () => api.get('/security-score')

// ── Benchmark ─────────────────────────────────────────────────
export const runBenchmark = (data) => api.post('/benchmark', data)

// ── Health ────────────────────────────────────────────────────
export const healthCheck = () => axios.get('http://127.0.0.1:8000/health')

export default api
