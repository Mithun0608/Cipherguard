import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Play, RefreshCw, Cpu, Zap, FlaskConical, Target,
  Shield, AlertTriangle, CheckCircle, Clock, Hash, Settings,
  ChevronDown, Info, ToggleLeft, ToggleRight, Search, Globe
} from 'lucide-react'
import Terminal, { useTerminal } from '../components/ui/Terminal'
import { Badge, RiskBadge } from '../components/ui/Badges'
import { ProgressBar } from '../components/ui/Charts'
import { runAttack, generateDataset } from '../services/api'

const ALGORITHMS = [
  { id: 'plaintext',     label: 'Plaintext',     tier: 'critical', desc: 'No hashing — direct comparison' },
  { id: 'md5',           label: 'MD5',           tier: 'critical', desc: 'Broken — collision attacks exist' },
  { id: 'sha1',          label: 'SHA-1',         tier: 'weak',     desc: 'Deprecated — rainbow tables' },
  { id: 'sha256',        label: 'SHA-256',       tier: 'weak',     desc: 'Fast — no key stretching' },
  { id: 'salted_sha256', label: 'Salted SHA-256',tier: 'moderate', desc: 'Salt adds rainbow resistance' },
  { id: 'bcrypt',        label: 'bcrypt',        tier: 'strong',   desc: 'Cost factor — adaptive slow' },
  { id: 'argon2id',      label: 'Argon2id',      tier: 'strong',   desc: 'Winner PHC — GPU resistant' },
]

const ATTACKS = [
  { id: 'dictionary',    label: 'Dictionary',    icon: '📖', desc: 'Common password wordlist matching',  color: 'cyan'   },
  { id: 'brute_force',   label: 'Brute Force',   icon: '💥', desc: 'Exhaustive combination enumeration', color: 'purple' },
  { id: 'rainbow_table', label: 'Rainbow Table', icon: '🌈', desc: 'Precomputed hash lookup tables',     color: 'yellow' },
  { id: 'hybrid',        label: 'Hybrid',        icon: '🧬', desc: 'Dictionary + mutation rules',        color: 'orange' },
]

const TIER_STYLES = {
  critical: { border: 'border-cyber-red/50',    bg: 'bg-cyber-red/10',    text: 'text-cyber-red',    badge: 'red'    },
  weak:     { border: 'border-yellow-400/50',   bg: 'bg-yellow-400/10',   text: 'text-yellow-400',   badge: 'yellow' },
  moderate: { border: 'border-cyber-cyan/50',   bg: 'bg-cyber-cyan/10',   text: 'text-cyber-cyan',   badge: 'cyan'   },
  strong:   { border: 'border-cyber-green/50',  bg: 'bg-cyber-green/10',  text: 'text-cyber-green',  badge: 'green'  },
}

const ATK_COLORS = {
  cyan:   { border: 'border-cyber-cyan/50',   bg: 'bg-cyber-cyan/10',   text: 'text-cyber-cyan'   },
  purple: { border: 'border-cyber-purple/50', bg: 'bg-cyber-purple/10', text: 'text-cyber-purple' },
  yellow: { border: 'border-yellow-400/50',   bg: 'bg-yellow-400/10',   text: 'text-yellow-400'   },
  orange: { border: 'border-orange-400/50',   bg: 'bg-orange-400/10',   text: 'text-orange-400'   },
}

// Algorithms where timeout does NOT imply security
const TIMEOUT_VULNERABLE_ALGOS = new Set(['plaintext', 'md5', 'sha1', 'sha256', 'salted_sha256'])

function AlgoButton({ algo, selected, onClick }) {
  const t = TIER_STYLES[algo.tier]
  const isSelected = selected === algo.id
  return (
    <motion.button
      onClick={() => onClick(algo.id)}
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.97 }}
      className={`relative p-3 rounded-xl border text-left transition-all duration-200 ${
        isSelected
          ? `${t.border} ${t.bg} shadow-inner`
          : 'border-cyber-border/30 bg-cyber-card/40 hover:border-cyber-border hover:bg-cyber-card/60'
      }`}
    >
      {isSelected && (
        <motion.div layoutId="algoSelected"
          className={`absolute inset-0 rounded-xl ${t.bg} opacity-50`} />
      )}
      <div className="relative z-10">
        <div className="flex items-center justify-between mb-1">
          <span className={`text-xs font-mono font-bold ${isSelected ? t.text : 'text-cyber-text'}`}>{algo.label}</span>
          {isSelected && <CheckCircle size={12} className={t.text} />}
        </div>
        <p className="text-[10px] text-cyber-muted font-mono leading-snug">{algo.desc}</p>
        <div className="mt-1.5">
          <Badge variant={t.badge}>{algo.tier}</Badge>
        </div>
      </div>
    </motion.button>
  )
}

function AttackButton({ attack, selected, onClick }) {
  const c = ATK_COLORS[attack.color]
  const isSelected = selected === attack.id
  return (
    <motion.button
      onClick={() => onClick(attack.id)}
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.97 }}
      className={`p-4 rounded-xl border text-left transition-all duration-200 ${
        isSelected
          ? `${c.border} ${c.bg}`
          : 'border-cyber-border/30 bg-cyber-card/40 hover:border-cyber-border'
      }`}
    >
      <div className="flex items-center gap-2 mb-1">
        <span className="text-lg">{attack.icon}</span>
        <span className={`text-sm font-mono font-bold ${isSelected ? c.text : 'text-cyber-text'}`}>{attack.label}</span>
        {isSelected && <CheckCircle size={13} className={`${c.text} ml-auto`} />}
      </div>
      <p className="text-[10px] text-cyber-muted font-mono">{attack.desc}</p>
    </motion.button>
  )
}

function InfoRow({ label, value, color = 'text-cyber-text' }) {
  if (!value) return null
  return (
    <div className="flex items-start gap-2 py-1.5 border-b border-cyber-border/15 last:border-0">
      <span className="text-[10px] font-mono text-cyber-muted flex-shrink-0 w-28 pt-0.5">{label}</span>
      <span className={`text-[11px] font-mono flex-1 leading-snug ${color}`}>{value}</span>
    </div>
  )
}

export default function ExperimentRunner() {
  const [algo,        setAlgo]        = useState('md5')
  const [attack,      setAttack]      = useState('dictionary')
  const [limit,       setLimit]       = useState(30)
  const [maxAttempts, setMaxAttempts] = useState(500000)
  const [timeout,     _setTimeout]    = useState(30)
  const [demoMode,    setDemoMode]    = useState(false)
  const [running,     setRunning]     = useState(false)
  const [result,      setResult]      = useState(null)
  const [progress,    setProgress]    = useState(0)
  const term = useTerminal()

  const selectedAlgo = ALGORITHMS.find(a => a.id === algo)
  const tier = TIER_STYLES[selectedAlgo?.tier || 'weak']
  const isBruteForce = attack === 'brute_force'

  // Determine if result shows a real timeout warning (not just bcrypt/argon2id resistance)
  const isTimeoutVulnerable = TIMEOUT_VULNERABLE_ALGOS.has(algo)
  const showTimeoutWarning  = result?.stopped_early && result?.cracked_count === 0 && isTimeoutVulnerable

  const runExperiment = async () => {
    setRunning(true); setResult(null); setProgress(0)
    term.clear()
    term.add(`╔══ CIPHERGUARD ATTACK ENGINE v3.0 ══╗`, 'cyan')
    term.add(`║  Algorithm  : ${algo.padEnd(20)}║`, 'dim')
    term.add(`║  Attack     : ${attack.padEnd(20)}║`, 'dim')
    term.add(`║  Targets    : ${String(limit).padEnd(20)}║`, 'dim')
    if (isBruteForce) {
      term.add(`║  Demo Mode  : ${String(demoMode).padEnd(20)}║`, demoMode ? 'success' : 'dim')
    }
    term.add(`╚══════════════════════════════════════╝`, 'cyan')
    term.sep()
    term.add('Initialising attack engine...', 'cyan')
    setProgress(15)
    term.add('Loading target hashes from database...', 'default')
    setProgress(30)

    if (algo === 'plaintext') {
      term.add('⚡ PLAINTEXT DETECTED — Instant compromise mode', 'error')
      term.add('Plaintext passwords are directly readable — no cracking needed.', 'error')
    }

    try {
      term.add(`Launching ${attack.replace('_', ' ')} attack on ${algo}...`, 'warn')
      if (isBruteForce && demoMode) {
        term.add('Demo mode: prioritizing short passwords for guaranteed cracking...', 'cyan')
      }
      setProgress(50)
      const r = await runAttack({
        attack_type: attack, algorithm: algo,
        max_attempts: maxAttempts, timeout_sec: timeout,
        target_limit: limit,
        demo_mode: isBruteForce ? demoMode : false,
      })
      const d = r.data
      setProgress(90)
      term.sep()
      term.add(`Attack Complete!`, 'success')

      // Correctly label timeout vs completion
      let statusLabel, statusType
      if (d.stopped_early && isTimeoutVulnerable) {
        statusLabel = 'TIMEOUT (≠ SECURE — algorithm still vulnerable)'
        statusType  = 'warn'
      } else if (d.stopped_early) {
        statusLabel = 'TIMEOUT (genuine computational resistance)'
        statusType  = 'success'
      } else {
        statusLabel = 'COMPLETE'
        statusType  = 'success'
      }

      term.add(`Status      : ${statusLabel}`, statusType)
      term.add(`Cracked     : ${d.cracked_count} / ${d.target_count}`, d.cracked_count > 0 ? 'error' : 'success')
      term.add(`Success Rate: ${d.success_rate_pct}%`, d.success_rate_pct > 0 ? 'error' : 'success')
      term.add(`Speed       : ${d.attempts_per_sec?.toLocaleString()} attempts/sec`, 'cyan')
      term.add(`Duration    : ${d.total_time_sec?.toFixed(3)}s`, 'default')

      if (d.cracked_sample?.length) {
        term.sep()
        term.add('Cracked Passwords (sample):', 'warn')
        d.cracked_sample.slice(0, 6).forEach(c => {
          term.add(`  → "${c.plain_password}"  (${c.crack_time_ms?.toFixed(4)}ms)`, 'error')
        })
      }

      term.sep()
      // Show timeout warning note if applicable
      if (d.timeout_note) {
        term.add(d.timeout_note, d.timeout_note.includes('≠') ? 'warn' : 'success')
        term.sep()
      }
      term.add(d.security_tier_note?.slice(0, 120) || '', 'dim')
      if (d.search_space_info) term.add(`Space: ${d.search_space_info}`, 'dim')
      if (d.gpu_crack_estimate) term.add(`GPU time: ${d.gpu_crack_estimate}`, 'dim')
      if (d.owasp_status) term.add(`OWASP: ${d.owasp_status.slice(0, 80)}`, 'dim')

      setResult(d)
      setProgress(100)
    } catch (e) {
      term.sep()
      term.add(`ERROR: ${e.message}`, 'error')
      term.add('Tip: Run dataset generation first if no hashes exist.', 'warn')
    } finally {
      setRunning(false)
    }
  }

  const genDataset = async () => {
    setRunning(true); setProgress(0)
    term.clear()
    term.add('Generating password dataset...', 'cyan')
    term.add('Algorithms : all 7 | Sample size: 50', 'dim')
    setProgress(20)
    try {
      const r = await generateDataset({ sample_size: 50, clear_existing: true })
      const d = r.data
      setProgress(100)
      term.add(`Created ${d.total_hashes_created} hashes from ${d.total_passwords} passwords.`, 'success')
      d.algorithms_used?.forEach(a => term.add(`  ✓ ${a}`, 'success'))
      term.sep()
      term.add('TIP: For brute force demo, use Demo Mode (short passwords only).', 'cyan')
    } catch (e) {
      term.add(`ERROR: ${e.message}`, 'error')
    } finally {
      setRunning(false)
    }
  }

  // Determine result banner state
  const getBannerState = () => {
    if (!result) return null
    if (result.cracked_count > 0) return 'compromised'
    if (result.stopped_early && isTimeoutVulnerable) return 'timeout_warning'
    if (result.stopped_early) return 'resisted_by_design'
    return 'resisted'
  }
  const bannerState = getBannerState()

  const BANNER_CONFIG = {
    compromised:        { border: 'border-neon-red',      icon: <AlertTriangle size={16} className="text-cyber-red" />,   label: 'VULNERABILITY CONFIRMED',             textColor: 'text-cyber-red'   },
    timeout_warning:    { border: 'border-yellow-400/50', icon: <AlertTriangle size={16} className="text-yellow-400" />,  label: 'TIMEOUT — NOT CRYPTOGRAPHICALLY SECURE', textColor: 'text-yellow-400' },
    resisted_by_design: { border: 'border-neon-green',    icon: <Shield size={16} className="text-cyber-green" />,        label: 'ATTACK RESISTED (Adaptive Hardness)',   textColor: 'text-cyber-green' },
    resisted:           { border: 'border-neon-green',    icon: <Shield size={16} className="text-cyber-green" />,        label: 'ATTACK RESISTED',                      textColor: 'text-cyber-green' },
  }

  return (
    <div className="page-container">
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">

        {/* ── Config Panel ──────────────────────────────────────── */}
        <motion.div initial={{ opacity: 0, x: -24 }} animate={{ opacity: 1, x: 0 }} className="space-y-5">

          {/* Algorithm selector */}
          <div className="glass-card p-5">
            <div className="flex items-center gap-2 mb-4">
              <div className="w-8 h-8 rounded-lg bg-cyber-cyan/10 border border-cyber-cyan/30 flex items-center justify-center">
                <Target size={15} className="text-cyber-cyan" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-cyber-text">Target Algorithm</h3>
                <p className="text-[10px] text-cyber-muted font-mono">Select hashing scheme to attack</p>
              </div>
              <div className="ml-auto">
                <Badge variant={tier.badge}>{selectedAlgo?.tier?.toUpperCase()}</Badge>
              </div>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-2 2xl:grid-cols-3 gap-2">
              {ALGORITHMS.map(a => (
                <AlgoButton key={a.id} algo={a} selected={algo} onClick={setAlgo} />
              ))}
            </div>
          </div>

          {/* Attack type */}
          <div className="glass-card p-5">
            <div className="flex items-center gap-2 mb-4">
              <div className="w-8 h-8 rounded-lg bg-cyber-red/10 border border-cyber-red/30 flex items-center justify-center">
                <Zap size={15} className="text-cyber-red" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-cyber-text">Attack Vector</h3>
                <p className="text-[10px] text-cyber-muted font-mono">Choose simulation mode</p>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              {ATTACKS.map(a => (
                <AttackButton key={a.id} attack={a} selected={attack} onClick={setAttack} />
              ))}
            </div>

            {/* Demo mode toggle — only visible for brute force */}
            <AnimatePresence>
              {isBruteForce && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="mt-4 overflow-hidden"
                >
                  <div className={`flex items-center gap-3 p-3 rounded-xl border transition-all ${
                    demoMode ? 'border-cyber-green/40 bg-cyber-green/5' : 'border-cyber-border/30 bg-cyber-card/30'
                  }`}>
                    <button
                      onClick={() => setDemoMode(p => !p)}
                      className="flex items-center gap-2 flex-1"
                    >
                      {demoMode
                        ? <ToggleRight size={22} className="text-cyber-green" />
                        : <ToggleLeft size={22} className="text-cyber-muted" />
                      }
                      <div className="text-left">
                        <p className={`text-xs font-mono font-bold ${demoMode ? 'text-cyber-green' : 'text-cyber-muted'}`}>
                          {demoMode ? 'DEMO MODE ON' : 'DEMO MODE OFF'}
                        </p>
                        <p className="text-[10px] text-cyber-muted font-mono leading-snug">
                          {demoMode
                            ? 'Uses short passwords (3-5 chars) — guarantees successful cracking'
                            : 'Standard mode — may timeout on longer passwords'}
                        </p>
                      </div>
                    </button>
                    <Badge variant={demoMode ? 'green' : 'gray'}>{demoMode ? 'ACTIVE' : 'OFF'}</Badge>
                  </div>
                  {!demoMode && (
                    <p className="text-[10px] text-yellow-400/70 font-mono mt-2 pl-1">
                      ⚠ Without demo mode, brute force may timeout. Timeout ≠ algorithm security.
                    </p>
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Parameters */}
          <div className="glass-card p-5">
            <div className="flex items-center gap-2 mb-4">
              <div className="w-8 h-8 rounded-lg bg-cyber-purple/10 border border-cyber-purple/30 flex items-center justify-center">
                <Settings size={15} className="text-cyber-purple" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-cyber-text">Attack Parameters</h3>
                <p className="text-[10px] text-cyber-muted font-mono">Tune intensity and limits</p>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-4">
              {[
                { label: 'Target Hashes', val: limit,       set: setLimit,       min: 5,    max: 200,    step: 5   },
                { label: 'Max Attempts',  val: maxAttempts, set: setMaxAttempts, min: 1000, max: 500000, step: 5000 },
                { label: 'Timeout (sec)', val: timeout,     set: _setTimeout,    min: 5,    max: 120,    step: 5   },
              ].map(({ label, val, set, min, max, step }) => (
                <div key={label}>
                  <label className="text-[10px] text-cyber-muted font-mono mb-1.5 block uppercase tracking-wide">{label}</label>
                  <input type="number" value={val} min={min} max={max} step={step}
                    onChange={e => set(Number(e.target.value))}
                    className="cyber-input text-center font-bold" />
                  <div className="mt-1.5">
                    <ProgressBar value={val - min} max={max - min} color="#8b5cf6" height={3} />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Action buttons */}
          <div className="grid grid-cols-2 gap-3">
            <button onClick={genDataset} disabled={running}
              className="btn-purple disabled:opacity-40 disabled:cursor-not-allowed py-3">
              <FlaskConical size={16} />
              Generate Dataset
            </button>
            <button onClick={runExperiment} disabled={running}
              className="btn-solid-cyan disabled:opacity-40 disabled:cursor-not-allowed py-3">
              {running ? <RefreshCw size={16} className="animate-spin" /> : <Play size={16} />}
              {running ? 'Attacking...' : 'Launch Attack'}
            </button>
          </div>

          {/* Progress */}
          {running && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="glass-card p-4">
              <div className="flex justify-between text-xs font-mono text-cyber-muted mb-2">
                <span>Attack in progress...</span>
                <span className="text-cyber-cyan">{progress}%</span>
              </div>
              <ProgressBar value={progress} max={100} color="#00f5ff" height={6} />
            </motion.div>
          )}

          {/* Result summary */}
          <AnimatePresence>
            {result && bannerState && (() => {
              const cfg = BANNER_CONFIG[bannerState]
              return (
                <motion.div
                  initial={{ opacity: 0, y: 12, scale: 0.98 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: -8 }}
                  className={`glass-card p-5 border ${cfg.border}`}
                >
                  <div className="flex items-center gap-2 mb-3">
                    {cfg.icon}
                    <span className={`text-sm font-bold ${cfg.textColor}`}>{cfg.label}</span>
                  </div>

                  {/* Timeout warning — critical education message */}
                  {showTimeoutWarning && (
                    <div className="mb-3 p-3 bg-yellow-400/5 border border-yellow-400/20 rounded-xl">
                      <p className="text-[11px] font-mono text-yellow-400 leading-relaxed">
                        ⚠ <strong>TIMEOUT ≠ SECURE:</strong> {algo.toUpperCase()} is still vulnerable.
                        Real GPU hardware is ~100,000× faster than this Python simulation.
                        {isBruteForce && !demoMode && ' Enable Demo Mode to see successful cracks.'}
                      </p>
                    </div>
                  )}

                  {/* Key metrics */}
                  <div className="grid grid-cols-3 gap-3 text-center mb-4">
                    {[
                      { label: 'Cracked', value: `${result.cracked_count}/${result.target_count}`, color: result.cracked_count > 0 ? 'text-cyber-red' : 'text-cyber-green' },
                      { label: 'Rate', value: `${result.success_rate_pct}%`, color: result.success_rate_pct > 0 ? 'text-cyber-red' : 'text-cyber-green' },
                      { label: 'Speed', value: `${(result.attempts_per_sec / 1000).toFixed(1)}k/s`, color: 'text-cyber-purple' },
                    ].map(({ label, value, color }) => (
                      <div key={label} className="bg-cyber-card/50 rounded-xl p-3 border border-cyber-border/30">
                        <p className={`text-xl font-extrabold font-mono ${color}`}>{value}</p>
                        <p className="text-[10px] text-cyber-muted mt-1">{label}</p>
                      </div>
                    ))}
                  </div>

                  {/* Extended analytics */}
                  <div className="space-y-0.5">
                    <InfoRow
                      label="Interpretation"
                      value={result.attack_interpretation || result.security_tier_note}
                      color="text-cyber-text/80"
                    />
                    {result.search_space_info && (
                      <InfoRow label="Search Space" value={result.search_space_info} color="text-cyber-cyan" />
                    )}
                    {result.gpu_crack_estimate && (
                      <InfoRow
                        label="GPU Crack Time"
                        value={result.gpu_crack_estimate}
                        color={result.gpu_crack_estimate.includes('year') ? 'text-cyber-green' : 'text-cyber-red'}
                      />
                    )}
                    {result.owasp_status && (
                      <InfoRow label="OWASP Status" value={result.owasp_status} color="text-cyber-muted" />
                    )}
                  </div>
                </motion.div>
              )
            })()}
          </AnimatePresence>
        </motion.div>

        {/* ── Terminal Panel ────────────────────────────────────── */}
        <motion.div initial={{ opacity: 0, x: 24 }} animate={{ opacity: 1, x: 0 }} className="min-h-[600px]">
          <Terminal lines={term.lines} running={running} title="CIPHERGUARD ATTACK ENGINE v3.0" />
        </motion.div>
      </div>
    </div>
  )
}
