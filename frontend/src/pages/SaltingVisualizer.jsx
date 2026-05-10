import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Layers, Hash, RefreshCw, Copy, Check, ShieldCheck, ShieldAlert, Zap, Info, ArrowRight } from 'lucide-react'
import { Badge } from '../components/ui/Badges'
import { hashPassword } from '../services/api'

const ALGOS = ['plaintext', 'md5', 'sha1', 'sha256', 'salted_sha256']
const BCRYPT_ALGOS = ['bcrypt', 'argon2id']

const ALGO_META = {
  plaintext:     { color: '#ff3366', label: 'Plaintext',      risk: 'CRITICAL', salted: false, desc: 'Stored as-is — maximum risk' },
  md5:           { color: '#ff3366', label: 'MD5',            risk: 'CRITICAL', salted: false, desc: '128-bit, fully broken' },
  sha1:          { color: '#ff8c00', label: 'SHA-1',          risk: 'HIGH',     salted: false, desc: '160-bit, deprecated' },
  sha256:        { color: '#ffd700', label: 'SHA-256',        risk: 'MEDIUM',   salted: false, desc: '256-bit, fast — no stretching' },
  salted_sha256: { color: '#00f5ff', label: 'Salted SHA-256', risk: 'LOW',      salted: true,  desc: 'SHA-256 + random salt' },
}

const RISK_BADGE = {
  CRITICAL: 'red', HIGH: 'red', MEDIUM: 'yellow', LOW: 'cyan', SAFE: 'green'
}

function HashCard({ algo, result, loading, delay = 0 }) {
  const [copied, setCopied] = useState(false)
  const meta = ALGO_META[algo] || { color: '#00f5ff', label: algo, risk: 'UNKNOWN', salted: false }

  const copy = () => {
    navigator.clipboard.writeText(result?.hash_value || '')
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <motion.div
      layout
      initial={{ opacity: 0, scale: 0.95, y: 12 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      transition={{ delay, duration: 0.4 }}
      className="glass-card p-4 border transition-all duration-200 hover:-translate-y-1"
      style={{ borderColor: `${meta.color}25`, background: `linear-gradient(135deg, ${meta.color}06 0%, transparent 60%)` }}
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full flex-shrink-0"
            style={{ background: meta.color, boxShadow: `0 0 8px ${meta.color}`, animation: result ? 'none' : 'pulse 2s infinite' }} />
          <span className="text-xs font-mono font-extrabold" style={{ color: meta.color }}>{meta.label}</span>
        </div>
        <div className="flex items-center gap-2">
          {meta.salted && <Badge variant="cyan">SALTED</Badge>}
          <Badge variant={RISK_BADGE[meta.risk] || 'gray'}>{meta.risk}</Badge>
          {result && (
            <button onClick={copy}
              className="p-1 rounded text-cyber-muted hover:text-cyber-cyan transition-colors">
              {copied ? <Check size={12} className="text-cyber-green" /> : <Copy size={12} />}
            </button>
          )}
        </div>
      </div>

      {/* Hash output */}
      {loading ? (
        <div className="space-y-2">
          <div className="skeleton h-3 w-full" />
          <div className="skeleton h-3 w-4/5" />
          <div className="skeleton h-3 w-3/5" />
        </div>
      ) : result ? (
        <>
          <div className="rounded-lg p-3 border font-mono text-xs break-all leading-relaxed"
            style={{
              background: 'rgba(0,0,0,0.4)',
              borderColor: `${meta.color}20`,
              color: meta.color,
              textShadow: `0 0 8px ${meta.color}40`,
              wordBreak: 'break-all'
            }}>
            {result.hash_value}
          </div>
          {result.salt && (
            <div className="mt-2 text-[10px] font-mono">
              <span className="text-cyber-muted">SALT: </span>
              <span className="text-cyber-cyan">{result.salt.slice(0, 28)}...</span>
            </div>
          )}
          <div className="mt-2 flex justify-between text-[10px] font-mono text-cyber-muted">
            <span className="flex items-center gap-1">
              <Hash size={9} />{result.hash_value?.length} chars
            </span>
            <span>{result.time_to_hash_ms?.toFixed(4)}ms</span>
          </div>
          <p className="text-[10px] font-mono text-cyber-muted/60 mt-1">{meta.desc}</p>
        </>
      ) : (
        <div className="text-center text-cyber-muted/30 font-mono text-xs py-5 flex flex-col items-center gap-1.5">
          <Hash size={16} className="opacity-30" />
          Enter password to generate
        </div>
      )}
    </motion.div>
  )
}

function ComparePane({ runA, runB }) {
  if (!runA || !runB) return null
  const same = runA.results?.salted_sha256?.hash_value === runB.results?.salted_sha256?.hash_value
  return (
    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
      className="glass-card p-5 border border-cyber-cyan/20">
      <h3 className="text-sm font-bold text-cyber-text mb-1 flex items-center gap-2">
        <Layers size={14} className="text-cyber-cyan" /> Run-to-Run Salt Comparison
      </h3>
      <p className="text-xs text-cyber-muted font-mono mb-4">
        Same password, different salt → different hash each time (rainbow tables defeated)
      </p>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {[runA, runB].map((run, i) => (
          <div key={i} className="bg-cyber-card/50 rounded-xl p-4 border border-cyber-border/30">
            <p className="text-[10px] font-mono text-cyber-muted mb-2">
              Run #{i + 1} — {run.time} — "{run.pwd}"
            </p>
            <div className="text-xs font-mono text-cyber-cyan break-all bg-black/30 rounded-lg p-3 border border-cyber-cyan/10 leading-relaxed">
              {run.results?.salted_sha256?.hash_value || '—'}
            </div>
            {run.results?.salted_sha256?.salt && (
              <div className="text-[10px] font-mono text-cyber-muted mt-2">
                Salt: <span className="text-cyber-purple">{run.results.salted_sha256.salt.slice(0, 32)}...</span>
              </div>
            )}
          </div>
        ))}
      </div>
      <motion.div
        initial={{ opacity: 0 }} animate={{ opacity: 1 }}
        className={`mt-4 p-3 rounded-xl border text-xs font-mono flex items-center gap-2 ${
          same
            ? 'border-yellow-400/30 bg-yellow-400/5 text-yellow-400'
            : 'border-cyber-green/30 bg-cyber-green/5 text-cyber-green'
        }`}>
        {same
          ? <><ShieldAlert size={14} /> SAME HASH — No salt applied (hash reuse vulnerability)</>
          : <><ShieldCheck size={14} /> UNIQUE HASHES — Salting prevents rainbow table lookup. Each run is cryptographically unique.</>
        }
      </motion.div>
    </motion.div>
  )
}

export default function SaltingVisualizer() {
  const [pwd,     setPwd]     = useState('')
  const [results, setResults] = useState({})
  const [loading, setLoading] = useState(false)
  const [runs,    setRuns]    = useState([])
  const [error,   setError]   = useState('')

  const hashAll = async () => {
    if (!pwd.trim()) return
    setLoading(true); setError('')
    const newRes = {}
    try {
      await Promise.all(ALGOS.map(async a => {
        try {
          const r = await hashPassword({ password: pwd, algorithm: a })
          newRes[a] = r.data
        } catch {}
      }))
      setResults(newRes)
      const ts = new Date().toLocaleTimeString('en-US', { hour12: false })
      setRuns(p => [...p.slice(-1), { pwd, results: newRes, time: ts }])
    } catch (e) {
      setError(e.message)
    }
    setLoading(false)
  }

  const hashDiff = results?.salted_sha256 && runs[0]?.results?.salted_sha256
    ? results.salted_sha256.hash_value !== runs[0].results.salted_sha256.hash_value : null

  const unsaltedAlgos = ['md5', 'sha1', 'sha256', 'plaintext']

  return (
    <div className="page-container">

      {/* ── Info Banner ───────────────────────────────────────── */}
      <motion.div initial={{ opacity: 0, y: -12 }} animate={{ opacity: 1, y: 0 }}
        className="card-cyan p-5">
        <div className="flex items-start gap-4">
          <div className="w-10 h-10 rounded-xl bg-cyber-cyan/10 border border-cyber-cyan/30 flex items-center justify-center flex-shrink-0">
            <Layers size={18} className="text-cyber-cyan" />
          </div>
          <div className="flex-1">
            <h3 className="text-sm font-bold text-cyber-text mb-1">Salting Visualizer</h3>
            <p className="text-xs text-cyber-muted font-mono mb-3">
              Hash the same password multiple times. Salted algorithms produce a <span className="text-cyber-cyan">unique hash each run</span>,
              defeating precomputed rainbow tables. Unsalted algorithms always produce the <span className="text-cyber-red">same deterministic output</span>.
            </p>
            <div className="flex gap-3 flex-wrap">
              {[
                { icon: ShieldCheck, text: 'Salted → unique every time',   color: 'text-cyber-green' },
                { icon: ShieldAlert, text: 'Unsalted → same hash always',  color: 'text-cyber-red'   },
                { icon: Zap,         text: 'Rainbow tables defeated by salt', color: 'text-cyber-cyan' },
              ].map(({ icon: I, text, color }) => (
                <div key={text} className="flex items-center gap-1.5 text-[11px] font-mono">
                  <I size={12} className={color} />
                  <span className={color}>{text}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </motion.div>

      {/* ── Input Panel ───────────────────────────────────────── */}
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}
        className="glass-card p-5 border border-cyber-border/40">
        <h3 className="text-sm font-bold text-cyber-text mb-3 flex items-center gap-2">
          <Hash size={14} className="text-cyber-cyan" /> Password Input
        </h3>
        <div className="flex gap-3">
          <input
            value={pwd}
            onChange={e => setPwd(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && hashAll()}
            placeholder='Enter any password (e.g. "monkey123", "P@ssw0rd", "hello")'
            className="cyber-input flex-1"
          />
          <button onClick={hashAll} disabled={loading || !pwd.trim()}
            className="btn-solid-cyan px-6 disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap">
            {loading ? <RefreshCw size={16} className="animate-spin" /> : <Hash size={16} />}
            {loading ? 'Hashing...' : 'Hash It'}
          </button>
        </div>
        {error && (
          <p className="text-xs text-cyber-red font-mono mt-2">Error: {error}</p>
        )}
        {pwd && (
          <p className="text-[10px] text-cyber-muted font-mono mt-2">
            Press Enter or click Hash It to generate all 5 algorithm outputs simultaneously
          </p>
        )}
      </motion.div>

      {/* ── Hash Grid ─────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
        {ALGOS.map((a, i) => (
          <HashCard key={a} algo={a} result={results[a]} loading={loading} delay={i * 0.07} />
        ))}
      </div>

      {/* ── Run Comparison ────────────────────────────────────── */}
      {runs.length >= 1 && results['salted_sha256'] && (
        <ComparePane runA={runs[0]} runB={{ pwd, results, time: new Date().toLocaleTimeString('en-US', { hour12: false }) }} />
      )}

      {/* ── Unsalted Vulnerability Showcase ───────────────────── */}
      {results['md5'] && (
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }} className="card-red p-5">
          <div className="flex items-center gap-2 mb-2">
            <ShieldAlert size={16} className="text-cyber-red animate-pulse" />
            <h3 className="text-sm font-bold text-cyber-red">Unsalted Vulnerability — Rainbow Table Attack</h3>
          </div>
          <p className="text-xs text-cyber-muted font-mono mb-4">
            These algorithms produce the <span className="text-cyber-red font-bold">exact same hash</span> for "
            {pwd}" every time. An attacker with a precomputed rainbow table cracks them instantly.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {unsaltedAlgos.map(a => results[a] && (
              <div key={a} className="bg-black/30 rounded-xl p-3 border border-cyber-red/20">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-[10px] text-cyber-red font-mono font-bold">{a.toUpperCase()} (NO SALT)</p>
                  <Badge variant="red">VULNERABLE</Badge>
                </div>
                <p className="text-xs font-mono text-cyber-text/50 break-all leading-relaxed bg-black/20 rounded p-2">
                  {results[a].hash_value}
                </p>
                <p className="text-[9px] text-cyber-red/60 mt-1.5 font-mono">
                  ↳ This hash is IDENTICAL on every run — rainbow table match guaranteed
                </p>
              </div>
            ))}
          </div>
          <div className="mt-4 p-3 bg-cyber-green/5 border border-cyber-green/20 rounded-xl">
            <div className="flex items-center gap-2 text-xs font-mono text-cyber-green">
              <ArrowRight size={13} />
              <span>Solution: Use <strong>salted_sha256</strong>, <strong>bcrypt</strong>, or <strong>argon2id</strong> — each run generates a cryptographically unique hash.</span>
            </div>
          </div>
        </motion.div>
      )}

      {/* Empty state */}
      {!results['md5'] && !loading && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
          className="glass-card p-10 text-center border border-cyber-border/20">
          <Hash size={40} className="mx-auto mb-3 text-cyber-cyan/20" />
          <p className="text-sm font-bold text-cyber-text mb-2">Enter a Password Above</p>
          <p className="text-xs text-cyber-muted font-mono">
            Type any password and click "Hash It" to see all 5 algorithms generate their outputs simultaneously
          </p>
        </motion.div>
      )}
    </div>
  )
}
