import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  BarChart, Bar, LineChart, Line, AreaChart, Area,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie, RadialBarChart, RadialBar, Legend
} from 'recharts'
import {
  Shield, Zap, Target, Database, ShieldAlert, ShieldCheck,
  Activity, Cpu, TrendingUp, TrendingDown, AlertTriangle,
  Eye, RefreshCw, Clock, Hash, Lock, Unlock
} from 'lucide-react'
import StatCard from '../components/ui/StatCard'
import { Badge, RiskBadge, GradeCircle } from '../components/ui/Badges'
import { CyberTooltip } from '../components/ui/Charts'
import { getSecurityScore, getAttackResults } from '../services/api'

const ALGO_COLORS = {
  plaintext: '#ff3366', md5: '#ff3366', sha1: '#ff8c00',
  sha256: '#ffd700', salted_sha256: '#00f5ff', bcrypt: '#8b5cf6', argon2id: '#00ff88',
}

// ── Live feed mock data ────────────────────────────────────────────────────
const INITIAL_FEED = [
  { time: '19:08:01', text: 'Dictionary attack initiated on MD5 (50 targets)',                type: 'info' },
  { time: '19:08:02', text: 'CRACKED  "monkey123"  →  MD5  (0.02ms) — instant GPU crack',  type: 'error' },
  { time: '19:08:03', text: 'CRACKED  "password"   →  SHA1 (0.15ms) — deprecated hash',   type: 'error' },
  { time: '19:08:04', text: 'Rainbow table built: 89 entries in 0.4ms — unsalted hashes vulnerable', type: 'info' },
  { time: '19:08:05', text: 'MD5 brute force TIMEOUT ≠ secure: GPU hardware 100,000x faster', type: 'warn' },
  { time: '19:08:06', text: 'MD5 score: F(17) — CRITICAL: fast, unsalted, broken algorithm', type: 'error' },
  { time: '19:08:07', text: 'Argon2id score: A+(95) — memory-hard, all 4 attacks FAILED',   type: 'success' },
  { time: '19:08:08', text: 'bcrypt resisted brute force (by design, NOT simulation timeout)', type: 'success' },
  { time: '19:08:09', text: 'Benchmark complete — ranking: Argon2id>bcrypt>S-SHA256>SHA256>SHA1>MD5>plain', type: 'success' },
]

function LiveFeedItem({ item, index }) {
  const colors = { info: 'text-cyber-cyan', success: 'text-cyber-green', error: 'text-cyber-red', warn: 'text-yellow-400' }
  const dots   = { info: 'bg-cyber-cyan', success: 'bg-cyber-green', error: 'bg-cyber-red', warn: 'bg-yellow-400' }
  return (
    <motion.div
      initial={{ opacity: 0, x: -16 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.07 }}
      className="flex items-start gap-3 py-2 border-b border-cyber-border/20 group hover:bg-cyber-cyan/2 transition-colors"
    >
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 mt-1.5 ${dots[item.type]}`} />
      <span className="text-cyber-muted/60 text-[10px] font-mono flex-shrink-0 mt-0.5">{item.time}</span>
      <span className={`text-xs font-mono flex-1 ${colors[item.type]}`}>{item.text}</span>
    </motion.div>
  )
}

function AlgoRankRow({ algo, score, rank, delay }) {
  const color = ALGO_COLORS[algo] || '#00f5ff'
  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay }}
      className="flex items-center gap-3 py-2 border-b border-cyber-border/20 hover:bg-cyber-card/30 transition-colors"
    >
      <span className="text-xs font-mono text-cyber-muted w-5 text-center">#{rank}</span>
      <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: color, boxShadow: `0 0 6px ${color}` }} />
      <span className="text-xs font-mono text-cyber-text flex-1 capitalize">
        {algo === 'salted_sha256' ? 'salted_sha256' : algo}
      </span>
      <div className="w-24 h-1.5 bg-cyber-border/30 rounded-full overflow-hidden">
        <motion.div
          className="h-full rounded-full"
          style={{ background: color, boxShadow: `0 0 6px ${color}60` }}
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ delay: delay + 0.3, duration: 0.8 }}
        />
      </div>
      <span className="text-xs font-mono w-7 text-right font-bold" style={{ color }}>{score}</span>
    </motion.div>
  )
}

export default function Dashboard() {
  const [scores,  setScores]  = useState(null)
  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(true)
  const [feedItems, setFeedItems] = useState(INITIAL_FEED)
  const feedRef = useRef(null)

  useEffect(() => {
    Promise.all([
      getSecurityScore().then(r => setScores(r.data)).catch(() => {}),
      getAttackResults({ limit: 50 }).then(r => setResults(r.data.results || [])).catch(() => {}),
    ]).finally(() => setLoading(false))
  }, [])

  // Simulate live feed updates with scientifically correct messages
  useEffect(() => {
    const msgs = [
      { text: 'Scanning for new attack results...', type: 'info' },
      { text: 'System health check passed — all modules online', type: 'success' },
      { text: 'NOTE: Attack timeout ≠ algorithm security. MD5/SHA1 still vulnerable.', type: 'warn' },
      { text: 'Argon2id: 64MB RAM per attempt — GPU brute force physically impractical', type: 'success' },
      { text: 'bcrypt cost=12: ~200ms/hash — adaptive slowness defeats mass cracking', type: 'success' },
      { text: 'MD5/SHA1: billions of hashes/sec on GPU — OWASP Forbidden algorithms', type: 'error' },
      { text: 'Plaintext: zero protection — instant database exposure on any breach', type: 'error' },
      { text: 'SHA256: cryptographically strong but NOT designed for password storage', type: 'warn' },
      { text: 'Salting defeats rainbow tables by making each hash unique per password', type: 'info' },
      { text: 'OWASP 2024 recommendation: migrate to Argon2id (primary) or bcrypt', type: 'info' },
    ]
    let i = 0
    const id = setInterval(() => {
      const now = new Date().toLocaleTimeString('en-US', { hour12: false })
      setFeedItems(p => [...p.slice(-12), { time: now, ...msgs[i % msgs.length] }])
      i++
    }, 5000)
    return () => clearInterval(id)
  }, [])

  const algoScores = scores?.algorithm_scores || []
  const sortedScores = [...algoScores].sort((a, b) => b.score - a.score)
  const weakest  = scores?.weakest_algorithm?.toUpperCase() || '—'
  const strongest = scores?.strongest_algorithm?.toUpperCase() || '—'
  const avgScore  = algoScores.length
    ? Math.round(algoScores.reduce((s, a) => s + a.score, 0) / algoScores.length) : 0

  const barData = sortedScores.map(a => ({
    name:  a.algorithm === 'salted_sha256' ? 'S-SHA256' : a.algorithm.toUpperCase(),
    score: a.score,
    algo:  a.algorithm,
  }))

  const tierPie = [
    { name: 'Weak',     value: algoScores.filter(a => a.score < 45).length,               fill: '#ff3366' },
    { name: 'Moderate', value: algoScores.filter(a => a.score >= 45 && a.score < 70).length, fill: '#ffd700' },
    { name: 'Strong',   value: algoScores.filter(a => a.score >= 70).length,               fill: '#00ff88' },
  ].filter(t => t.value > 0)

  const crackLineData = results.slice(0, 12).map((r, i) => ({
    name:   r.algorithm?.slice(0, 6).toUpperCase(),
    rate:   r.success_rate_pct,
    speed:  Math.min(r.attempts_per_sec / 1000, 100),
  }))

  const recentResults = results.slice(0, 8)

  return (
    <div className="page-container">

      {/* ── Threat Banner ────────────────────────────────────────── */}
      {scores && scores.overall_risk_level !== 'LOW' && (
        <motion.div
          initial={{ opacity: 0, y: -16 }}
          animate={{ opacity: 1, y: 0 }}
          className="card-red p-4 flex items-center gap-4"
        >
          <AlertTriangle size={20} className="text-cyber-red flex-shrink-0 animate-pulse" />
          <div className="flex-1">
            <p className="text-sm font-bold text-cyber-red">Security Alert — Weak Algorithms Detected</p>
            <p className="text-xs text-cyber-muted font-mono">
              {algoScores.filter(a => a.score < 40).map(a => a.algorithm.toUpperCase()).join(', ')} are critically vulnerable.
              Replace immediately with bcrypt or argon2id.
            </p>
          </div>
          <RiskBadge level={scores.overall_risk_level} />
        </motion.div>
      )}

      {/* ── Stat Cards ───────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatCard label="Algorithms" value={algoScores.length || 7}
          icon={Database} color="cyan" delay={0} loading={loading}
          sub="Evaluated" trend={0} />
        <StatCard label="Attacks Tested" value={results.length}
          icon={Zap} color="red" delay={0.05} loading={loading}
          sub="Simulated" trend={results.length > 0 ? 12 : 0} />
        <StatCard label="Most Secure" value={strongest}
          icon={ShieldCheck} color="green" delay={0.1} loading={loading}
          sub="Top algorithm" />
        <StatCard label="Most Vulnerable" value={weakest}
          icon={ShieldAlert} color="red" delay={0.15} loading={loading}
          sub="Weakest algo" />
        <StatCard label="Avg Score" value={avgScore || '—'}
          icon={Target} color="purple" delay={0.2} loading={loading}
          sub="/ 100 pts" unit="" />
        <StatCard
          label="Overall Risk"
          value={scores?.overall_risk_level || 'N/A'}
          icon={Activity}
          color={scores?.overall_risk_level === 'LOW' ? 'green' : 'red'}
          delay={0.25} loading={loading}
          sub="System threat level"
        />
      </div>

      {/* ── Charts Row 1 ─────────────────────────────────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">

        {/* Score Bar Chart */}
        <motion.div initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }} className="glass-card p-5 xl:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-cyber-text flex items-center gap-2">
                <Hash size={14} className="text-cyber-cyan" />
                Algorithm Security Scores
              </h3>
              <p className="text-xs text-cyber-muted font-mono">Composite 0–100 security rating</p>
            </div>
            {scores?.overall_risk_level && <RiskBadge level={scores.overall_risk_level} />}
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={barData} barSize={28} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
              <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} domain={[0, 100]} />
              <Tooltip content={<CyberTooltip />} />
              <Bar dataKey="score" name="Score" radius={[6, 6, 0, 0]}>
                {barData.map((e, i) => (
                  <Cell key={i} fill={ALGO_COLORS[e.algo] || '#00f5ff'}
                    style={{ filter: `drop-shadow(0 0 6px ${ALGO_COLORS[e.algo] || '#00f5ff'}80)` }} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </motion.div>

        {/* Tier Donut */}
        <motion.div initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.35 }} className="glass-card p-5">
          <h3 className="text-sm font-bold text-cyber-text mb-1 flex items-center gap-2">
            <Shield size={14} className="text-cyber-purple" />
            Tier Distribution
          </h3>
          <p className="text-xs text-cyber-muted font-mono mb-4">Security classification breakdown</p>
          <ResponsiveContainer width="100%" height={160}>
            <PieChart>
              <Pie data={tierPie} cx="50%" cy="50%" innerRadius={45} outerRadius={65}
                dataKey="value" paddingAngle={5} startAngle={90} endAngle={-270}>
                {tierPie.map((e, i) => (
                  <Cell key={i} fill={e.fill} style={{ filter: `drop-shadow(0 0 8px ${e.fill}60)` }} />
                ))}
              </Pie>
              <Tooltip content={<CyberTooltip />} />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex justify-center gap-4 mt-2">
            {tierPie.map(t => (
              <div key={t.name} className="flex items-center gap-1.5 text-xs font-mono">
                <span className="w-2 h-2 rounded-full" style={{ background: t.fill, boxShadow: `0 0 6px ${t.fill}` }} />
                <span className="text-cyber-muted">{t.name}</span>
                <span className="font-bold" style={{ color: t.fill }}>{t.value}</span>
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* ── Charts Row 2 ─────────────────────────────────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">

        {/* Crack Rate Area */}
        <motion.div initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }} className="glass-card p-5">
          <h3 className="text-sm font-bold text-cyber-text mb-1 flex items-center gap-2">
            <Zap size={14} className="text-cyber-red" />
            Attack Success Rates
          </h3>
          <p className="text-xs text-cyber-muted font-mono mb-4">Crack % per recorded experiment run</p>
          {crackLineData.length > 0 ? (
            <ResponsiveContainer width="100%" height={175}>
              <AreaChart data={crackLineData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="crackGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#ff3366" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ff3366" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 9, fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#64748b', fontSize: 9 }} axisLine={false} tickLine={false} domain={[0, 100]} />
                <Tooltip content={<CyberTooltip />} />
                <Area type="monotone" dataKey="rate" stroke="#ff3366" strokeWidth={2}
                  fill="url(#crackGrad)" dot={{ fill: '#ff3366', r: 3 }} name="Crack %" />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-44 flex flex-col items-center justify-center text-cyber-muted gap-2">
              <Cpu size={28} className="opacity-20" />
              <p className="text-sm font-mono">No results yet — run experiments first</p>
            </div>
          )}
        </motion.div>

        {/* Live Activity + Rankings */}
        <motion.div initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.45 }} className="glass-card p-5">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-cyber-text">Live Activity Feed</h3>
              <span className="w-2 h-2 rounded-full bg-cyber-green animate-pulse" />
            </div>
            <Badge variant="green">LIVE</Badge>
          </div>

          {/* Feed */}
          <div className="overflow-y-auto max-h-36 mb-4 pr-1">
            <AnimatePresence>
              {feedItems.slice(-8).map((e, i) => (
                <LiveFeedItem key={`${e.time}-${i}`} item={e} index={i} />
              ))}
            </AnimatePresence>
          </div>

          {/* Divider */}
          <div className="flex items-center gap-2 mb-3">
            <div className="flex-1 h-px bg-cyber-border/30" />
            <span className="text-[10px] font-mono text-cyber-muted">SCORE RANKINGS</span>
            <div className="flex-1 h-px bg-cyber-border/30" />
          </div>

          {/* Rankings */}
          <div>
            {sortedScores.slice(0, 5).map((a, i) => (
              <AlgoRankRow key={a.algorithm} algo={a.algorithm} score={a.score}
                rank={i + 1} delay={i * 0.08 + 0.5} />
            ))}
            {sortedScores.length === 0 && !loading && (
              <p className="text-xs text-cyber-muted font-mono text-center py-4">Run security analysis to see rankings</p>
            )}
          </div>
        </motion.div>
      </div>

      {/* ── Recent Results Table ──────────────────────────────────── */}
      {recentResults.length > 0 && (
        <motion.div initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.55 }} className="glass-card overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 border-b border-cyber-border/30">
            <div>
              <h3 className="text-sm font-bold text-cyber-text flex items-center gap-2">
                <Eye size={14} className="text-cyber-cyan" />
                Recent Attack Results
              </h3>
              <p className="text-xs text-cyber-muted font-mono">Latest simulation run data</p>
            </div>
            <Badge variant="cyan">{recentResults.length} runs</Badge>
          </div>
          <div className="overflow-x-auto">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Attack Type</th>
                  <th>Algorithm</th>
                  <th>Cracked / Total</th>
                  <th>Success Rate</th>
                  <th>Speed</th>
                  <th>Duration</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {recentResults.map((r, i) => (
                  <motion.tr key={r.id || i}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.04 }}
                  >
                    <td><Badge variant={{ dictionary: 'cyan', brute_force: 'purple', rainbow_table: 'yellow', hybrid: 'orange' }[r.attack_type] || 'gray'}>
                      {r.attack_type?.replace(/_/g, ' ')}
                    </Badge></td>
                    <td className="font-mono text-xs">{r.algorithm}</td>
                    <td>
                      <span className={`font-mono text-xs font-bold ${r.cracked_count > 0 ? 'text-cyber-red' : 'text-cyber-green'}`}>
                        {r.cracked_count}
                      </span>
                      <span className="text-cyber-muted font-mono text-xs"> / {r.target_count}</span>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <div className="progress-bar w-16">
                          <div className="progress-fill" style={{
                            width: `${r.success_rate_pct}%`,
                            background: r.success_rate_pct > 50 ? '#ff3366' : r.success_rate_pct > 0 ? '#ffd700' : '#00ff88'
                          }} />
                        </div>
                        <span className={`text-xs font-mono font-bold ${r.success_rate_pct > 50 ? 'text-cyber-red' : r.success_rate_pct > 0 ? 'text-yellow-400' : 'text-cyber-green'}`}>
                          {r.success_rate_pct}%
                        </span>
                      </div>
                    </td>
                    <td className="font-mono text-xs text-cyber-cyan">{r.attempts_per_sec?.toLocaleString()}/s</td>
                    <td className="font-mono text-xs text-cyber-muted">{r.total_time_sec?.toFixed(3)}s</td>
                    <td>
                      {r.stopped_early
                        ? <span title="Timeout ≠ Secure: weak algorithms remain vulnerable">
                            <Badge variant="yellow">TIMEOUT</Badge>
                          </span>
                        : <Badge variant="green">COMPLETE</Badge>
                      }
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>
      )}

      {/* Empty state */}
      {!loading && results.length === 0 && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.4 }}
          className="glass-card p-12 text-center border border-cyber-cyan/10">
          <Shield size={48} className="mx-auto mb-4 text-cyber-cyan/20" />
          <h3 className="text-lg font-bold text-cyber-text mb-2">No Data Yet</h3>
          <p className="text-sm text-cyber-muted font-mono mb-6">
            Go to <span className="text-cyber-cyan">Experiment Runner</span> → Generate Dataset → Launch an Attack
          </p>
          <div className="flex justify-center gap-3">
            <a href="/experiment" className="btn-solid-cyan">→ Start Experiment</a>
          </div>
        </motion.div>
      )}
    </div>
  )
}
