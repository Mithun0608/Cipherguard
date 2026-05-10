import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  AreaChart, Area, BarChart, Bar, Cell, PieChart, Pie
} from 'recharts'
import {
  Radiation, Play, RefreshCw, AlertTriangle, Shield,
  ShieldAlert, Clock, Database, Zap, TrendingUp, Download,
  CheckCircle, XCircle, Activity
} from 'lucide-react'
import { Badge, RiskBadge } from '../components/ui/Badges'
import { CyberTooltip, ProgressBar, ScoreRing } from '../components/ui/Charts'
import { runBenchmark, generateDataset } from '../services/api'

const WEAK_ALGOS  = ['md5', 'sha1', 'sha256', 'salted_sha256']
const ALGO_COLORS = { md5: '#ff3366', sha1: '#ff8c00', sha256: '#ffd700', salted_sha256: '#00f5ff' }

const SIM_PHASES = [
  { label: 'Initialising breach environment',        pct: 5  },
  { label: 'Generating leaked database (40 records)', pct: 20 },
  { label: 'Building dictionary wordlist',            pct: 35 },
  { label: 'Launching dictionary attack',             pct: 50 },
  { label: 'Running rainbow table lookup',            pct: 65 },
  { label: 'Executing brute force sweep',             pct: 78 },
  { label: 'Running hybrid attack mutations',         pct: 88 },
  { label: 'Computing breach impact score',           pct: 95 },
  { label: 'Generating incident report',              pct: 100 },
]

function TimelineEvent({ event, index }) {
  const colors = { error: 'text-cyber-red', success: 'text-cyber-green', warn: 'text-yellow-400', info: 'text-cyber-cyan' }
  const dots   = { error: 'bg-cyber-red border-cyber-red/30', success: 'bg-cyber-green border-cyber-green/30', warn: 'bg-yellow-400 border-yellow-400/30', info: 'bg-cyber-cyan border-cyber-cyan/30' }
  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.06 }}
      className="flex items-start gap-3 py-2.5 border-b border-cyber-border/15 group"
    >
      <div className="flex flex-col items-center gap-1 pt-1">
        <span className={`w-2.5 h-2.5 rounded-full border flex-shrink-0 ${dots[event.type] || dots.info}`} />
        <div className="w-px flex-1 bg-cyber-border/20 min-h-[12px]" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <span className="text-[10px] font-mono text-cyber-muted flex-shrink-0">{event.t}</span>
          {event.pct !== undefined && event.pct > 0 && (
            <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${event.pct > 50 ? 'bg-cyber-red/10 text-cyber-red' : 'bg-cyber-green/10 text-cyber-green'}`}>
              {event.pct}% compromised
            </span>
          )}
        </div>
        <p className={`text-xs font-mono ${colors[event.type] || 'text-cyber-text/70'}`}>{event.event}</p>
      </div>
    </motion.div>
  )
}

export default function BreachSimulator() {
  const [running,    setRunning]   = useState(false)
  const [report,     setReport]    = useState(null)
  const [timeline,   setTimeline]  = useState([])
  const [progress,   setProgress]  = useState(0)
  const [phase,      setPhase]     = useState('')
  const [phaseIndex, setPhaseIndex]= useState(0)

  const addEvent = (event) => setTimeline(p => [...p, event])

  const advancePhase = (idx) => {
    const ph = SIM_PHASES[idx]
    if (ph) { setPhase(ph.label); setProgress(ph.pct); setPhaseIndex(idx) }
  }

  const simulate = async () => {
    setRunning(true); setReport(null); setTimeline([]); setProgress(0); setPhaseIndex(0)
    advancePhase(0)

    try {
      addEvent({ t: 'T+0s',   type: 'warn',    pct: 0,   event: 'BREACH DETECTED — Attacker gained database access' })
      addEvent({ t: 'T+0.5s', type: 'info',    pct: 0,   event: 'Target: 40 user password hashes (md5, sha1, sha256, salted_sha256)' })

      advancePhase(1)
      await generateDataset({ sample_size: 40, algorithms: WEAK_ALGOS, clear_existing: true })
      addEvent({ t: 'T+1s',   type: 'error',   pct: 0,   event: 'Leaked database loaded — 160 hash records extracted' })

      advancePhase(2)
      addEvent({ t: 'T+2s',   type: 'info',    pct: 0,   event: 'Dictionary wordlist prepared: 14.3M common passwords' })

      advancePhase(3)
      addEvent({ t: 'T+3s',   type: 'error',   pct: 0,   event: 'Dictionary attack launched — targeting all 4 algorithms simultaneously' })

      advancePhase(4)
      const r = await runBenchmark({
        algorithms:    WEAK_ALGOS,
        target_limit:  20,
        max_attempts:  15000,
        timeout_sec:   12.0,
      })
      advancePhase(5)

      const d = r.data
      const perAlgo = d.per_algorithm || []

      perAlgo.forEach((a, i) => {
        const dict   = a.attacks?.dictionary
        const rainbow = a.attacks?.rainbow_table
        if (dict) addEvent({
          t:    `T+${i * 3 + 4}s`,
          pct:  dict.cracked_count || 0,
          event: `[${a.algorithm?.toUpperCase()}] Dictionary: cracked ${dict.cracked_count || 0} / 20 (${dict.success_rate_pct?.toFixed(0) || 0}%) @ ${dict.attempts_per_sec?.toLocaleString()}/sec`,
          type: (dict.cracked_count || 0) > 0 ? 'error' : 'success',
        })
        if (rainbow) addEvent({
          t:    `T+${i * 3 + 5}s`,
          pct:  rainbow.cracked_count || 0,
          event: `[${a.algorithm?.toUpperCase()}] Rainbow table: ${rainbow.cracked_count || 0} hash lookups matched`,
          type: (rainbow.cracked_count || 0) > 0 ? 'error' : 'success',
        })
      })

      advancePhase(6)
      addEvent({ t: 'T+18s', type: 'info', event: 'Hybrid mutations applied — 132 password variants tested' })

      const totalCracked   = perAlgo.reduce((s, a) => s + (a.attacks?.dictionary?.cracked_count || 0), 0)
      const totalTargets   = perAlgo.length * 20
      const compromisePct  = Math.round((totalCracked / Math.max(totalTargets, 1)) * 100)

      advancePhase(7)
      addEvent({ t: 'T+20s', type: 'error',   pct: compromisePct, event: `BREACH COMPLETE — ${compromisePct}% of accounts compromised` })
      addEvent({ t: 'T+21s', type: 'success',  event: `Strongest: ${d.benchmark_summary?.strongest_algorithm?.toUpperCase()} — all attacks failed` })
      addEvent({ t: 'T+22s', type: 'warn',    event: 'Incident report generated — see below for remediation steps' })

      advancePhase(8)
      setReport({ ...d, compromisePct, totalCracked, totalTargets })

    } catch (e) {
      addEvent({ t: 'ERR', type: 'error', event: `Simulation error: ${e.message}` })
    }
    setPhase('Complete'); setRunning(false)
  }

  const chartData = timeline
    .filter(t => t.pct !== undefined)
    .map((t, i) => ({ t: t.t, compromised: t.pct || 0 }))

  const pieData = report?.per_algorithm?.map(a => ({
    name:  a.algorithm,
    value: a.attacks?.dictionary?.cracked_count || 0,
    fill:  ALGO_COLORS[a.algorithm] || '#64748b',
  })) || []

  const exportReport = () => {
    if (!report) return
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
    a.download = 'breach_report.json'; a.click()
  }

  return (
    <div className="page-container">

      {/* ── Danger Header ─────────────────────────────────────── */}
      <motion.div initial={{ opacity: 0, y: -16 }} animate={{ opacity: 1, y: 0 }}
        className="card-red p-6">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-cyber-red/15 border border-cyber-red/40 flex items-center justify-center flex-shrink-0">
              <Radiation size={22} className="text-cyber-red animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <h3 className="text-base font-extrabold text-cyber-red">Breach Simulator</h3>
                <Badge variant="red">SIMULATION ONLY</Badge>
              </div>
              <p className="text-xs text-cyber-muted font-mono max-w-2xl">
                Simulates a real-world database breach: generates a dataset using weak hashing algorithms,
                then executes dictionary, rainbow table, brute force, and hybrid attacks to compute
                the real-world compromise rate and generate an incident response report.
              </p>
            </div>
          </div>
          <button onClick={simulate} disabled={running}
            className="btn-solid-red disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap py-3 px-6">
            {running ? <RefreshCw size={16} className="animate-spin" /> : <Play size={16} />}
            {running ? `${phase}...` : 'Launch Breach Simulation'}
          </button>
        </div>

        {running && (
          <div className="mt-5">
            <div className="flex justify-between text-xs font-mono text-cyber-muted mb-2">
              <span className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-cyber-red animate-pulse" />
                {phase}
              </span>
              <span className="text-cyber-red font-bold">{progress}%</span>
            </div>
            <div className="progress-bar h-2">
              <motion.div
                className="h-full rounded-full"
                style={{ background: 'linear-gradient(90deg, #ff3366, #ff8c00)' }}
                animate={{ width: `${progress}%` }}
                transition={{ duration: 0.5 }}
              />
            </div>
            <div className="mt-2 flex gap-1.5">
              {SIM_PHASES.map((ph, i) => (
                <div key={i}
                  className={`h-0.5 flex-1 rounded-full transition-all duration-500 ${
                    i < phaseIndex ? 'bg-cyber-red' : i === phaseIndex ? 'bg-cyber-red/60 animate-pulse' : 'bg-cyber-border/30'
                  }`}
                />
              ))}
            </div>
          </div>
        )}
      </motion.div>

      {/* ── Timeline + Chart ──────────────────────────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">

        {/* Event timeline */}
        <div className="glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-cyber-text flex items-center gap-2">
              <Clock size={14} className="text-cyber-red" /> Attack Timeline
            </h3>
            {timeline.length > 0 && <Badge variant="red">{timeline.length} events</Badge>}
          </div>
          <div className="overflow-y-auto max-h-72 pr-1">
            <AnimatePresence>
              {timeline.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 gap-3 text-cyber-muted">
                  <Radiation size={28} className="opacity-20" />
                  <p className="text-sm font-mono">Launch simulation to begin</p>
                </div>
              ) : (
                timeline.map((e, i) => <TimelineEvent key={i} event={e} index={i} />)
              )}
            </AnimatePresence>
          </div>
        </div>

        {/* Compromise progression */}
        <div className="glass-card p-5">
          <h3 className="text-sm font-bold text-cyber-text mb-1 flex items-center gap-2">
            <TrendingUp size={14} className="text-cyber-red" /> Compromise Progression
          </h3>
          <p className="text-xs text-cyber-muted font-mono mb-4">Accounts compromised over attack timeline</p>
          {chartData.length > 1 ? (
            <ResponsiveContainer width="100%" height={230}>
              <AreaChart data={chartData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="breachGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#ff3366" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#ff3366" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="t" tick={{ fill: '#64748b', fontSize: 9, fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} domain={[0, 100]} />
                <Tooltip content={<CyberTooltip />} />
                <Area type="monotone" dataKey="compromised" stroke="#ff3366" strokeWidth={2.5}
                  fill="url(#breachGrad)" name="Compromised %" dot={{ fill: '#ff3366', r: 4 }} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-52 flex items-center justify-center text-cyber-muted/30 text-xs font-mono flex-col gap-2">
              <Activity size={24} className="opacity-30" />
              Run simulation to see breach progression
            </div>
          )}
        </div>
      </div>

      {/* ── Impact Report ─────────────────────────────────────── */}
      {report && (
        <motion.div initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }}
          className="space-y-5">

          {/* Impact KPIs */}
          <div className="glass-card p-5 border border-cyber-red/20">
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-sm font-bold text-cyber-text flex items-center gap-2">
                <Radiation size={15} className="text-cyber-red" /> Breach Impact Report
              </h3>
              <button onClick={exportReport} className="btn-red text-xs">
                <Download size={13} /> Export JSON
              </button>
            </div>

            {/* KPI cards */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
              {[
                { label: 'Accounts Compromised', value: `${report.compromisePct}%`, color: 'text-cyber-red',   icon: ShieldAlert },
                { label: 'Algorithms Tested',    value: report.per_algorithm?.length || 4, color: 'text-cyber-cyan',  icon: Database },
                { label: 'Strongest Algorithm',  value: report.benchmark_summary?.strongest_algorithm?.toUpperCase() || '—', color: 'text-cyber-green', icon: Shield },
                { label: 'Overall Risk Level',   value: report.benchmark_summary?.overall_risk_level || '—', color: 'text-yellow-400', icon: AlertTriangle },
              ].map(({ label, value, color, icon: I }) => (
                <div key={label} className="bg-cyber-card/50 rounded-xl p-4 border border-cyber-border/30 text-center">
                  <I size={18} className={`mx-auto mb-2 ${color}`} />
                  <p className={`text-2xl font-extrabold font-mono ${color}`}>{value}</p>
                  <p className="text-xs text-cyber-muted mt-1 font-medium">{label}</p>
                </div>
              ))}
            </div>

            {/* Per-algo grid + pie */}
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
              <div className="xl:col-span-2 overflow-x-auto">
                <table className="cyber-table">
                  <thead>
                    <tr>
                      <th>Algorithm</th>
                      <th>Score</th>
                      <th>Grade</th>
                      <th>Dict Attack</th>
                      <th>Rainbow</th>
                      <th>Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(report.per_algorithm || []).map((a, i) => (
                      <motion.tr key={a.algorithm || i}
                        initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.07 }}>
                        <td>
                          <div className="flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full" style={{ background: ALGO_COLORS[a.algorithm] || '#64748b' }} />
                            <span className="font-mono text-xs font-bold">{a.algorithm}</span>
                          </div>
                        </td>
                        <td><span className="font-mono text-cyber-cyan font-bold">{a.score}</span></td>
                        <td>
                          <span className="font-mono text-lg font-extrabold" style={{
                            color: a.score >= 70 ? '#00ff88' : a.score >= 40 ? '#ffd700' : '#ff3366'
                          }}>{a.grade}</span>
                        </td>
                        <td>
                          <span className={`font-mono text-xs ${(a.attacks?.dictionary?.cracked_count || 0) > 0 ? 'text-cyber-red' : 'text-cyber-green'}`}>
                            {a.attacks?.dictionary?.cracked_count || 0} cracked
                          </span>
                        </td>
                        <td>
                          <span className={`font-mono text-xs ${(a.attacks?.rainbow_table?.cracked_count || 0) > 0 ? 'text-cyber-red' : 'text-cyber-green'}`}>
                            {a.attacks?.rainbow_table?.cracked_count || 0} cracked
                          </span>
                        </td>
                        <td>
                          <Badge variant={a.score >= 70 ? 'green' : a.score >= 40 ? 'yellow' : 'red'}>
                            {a.score >= 70 ? 'LOW' : a.score >= 40 ? 'MED' : 'HIGH'}
                          </Badge>
                        </td>
                      </motion.tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Cracked distribution pie */}
              <div>
                <p className="text-xs font-mono text-cyber-muted mb-3">Cracked Distribution</p>
                <ResponsiveContainer width="100%" height={160}>
                  <PieChart>
                    <Pie data={pieData} cx="50%" cy="50%" outerRadius={60}
                      dataKey="value" paddingAngle={3}>
                      {pieData.map((e, i) => (
                        <Cell key={i} fill={e.fill} style={{ filter: `drop-shadow(0 0 6px ${e.fill}60)` }} />
                      ))}
                    </Pie>
                    <Tooltip content={<CyberTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="space-y-1.5">
                  {pieData.map(d => (
                    <div key={d.name} className="flex items-center gap-2 text-xs font-mono">
                      <span className="w-2 h-2 rounded-full" style={{ background: d.fill }} />
                      <span className="text-cyber-muted flex-1">{d.name}</span>
                      <span style={{ color: d.fill }} className="font-bold">{d.value} cracked</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Remediation steps */}
          {report.recommendations?.length > 0 && (
            <div className="card-yellow p-5">
              <h3 className="text-sm font-bold text-cyber-text mb-4 flex items-center gap-2">
                <CheckCircle size={14} className="text-yellow-400" /> Remediation Steps
              </h3>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                {report.recommendations.map((r, i) => (
                  <div key={i} className="flex items-start gap-3 bg-cyber-card/40 rounded-xl p-3 border border-yellow-400/15">
                    <span className="text-yellow-400 text-xs flex-shrink-0 mt-0.5">▸</span>
                    <p className="text-xs text-cyber-text/80 font-mono leading-relaxed">{r}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </motion.div>
      )}
    </div>
  )
}
