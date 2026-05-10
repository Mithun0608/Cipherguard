import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { RefreshCw, Award, Shield, ShieldAlert, ShieldCheck, TrendingUp, TrendingDown, AlertTriangle, ChevronDown, ChevronUp } from 'lucide-react'
import { Badge, RiskBadge, GradeCircle } from '../components/ui/Badges'
import { ScoreRing, ProgressBar, CyberTooltip } from '../components/ui/Charts'
import { getSecurityScore } from '../services/api'

const ALGO_COLORS = {
  plaintext: '#ff3366', md5: '#ff3366', sha1: '#ff8c00',
  sha256: '#ffd700', salted_sha256: '#00f5ff', bcrypt: '#8b5cf6', argon2id: '#00ff88',
}

const TIER_CONFIG = {
  strong:   { bg: 'card-green',  border: 'border-neon-green',  badge: 'green',  icon: ShieldCheck, iconColor: 'text-cyber-green',  label: '✦ SECURE' },
  moderate: { bg: 'card-yellow', border: 'border-yellow-400/30', badge: 'yellow', icon: Shield,      iconColor: 'text-yellow-400',  label: '● MODERATE' },
  weak:     { bg: 'card-red',    border: 'border-neon-red',    badge: 'red',    icon: ShieldAlert,  iconColor: 'text-cyber-red',   label: '▲ VULNERABLE' },
}

const GRADE_ORDER = { 'A+': 95, A: 90, B: 75, C: 55, D: 35, F: 15 }

function AlgoCard({ algo, rank, delay }) {
  const [expanded, setExpanded] = useState(false)
  const color = ALGO_COLORS[algo.algorithm] || '#00f5ff'
  const tier  = algo.score >= 70 ? 'strong' : algo.score >= 40 ? 'moderate' : 'weak'
  const tc    = TIER_CONFIG[tier]
  const IconC = tc.icon

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 32, scale: 0.96 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ delay, duration: 0.45 }}
      whileHover={{ y: -4 }}
      className={`${tc.bg} overflow-hidden transition-all duration-300`}
      style={{ boxShadow: tier === 'strong' ? '0 0 30px rgba(0,255,136,0.08)' : tier === 'weak' ? '0 0 30px rgba(255,51,102,0.08)' : '' }}
    >
      {/* Rank badge */}
      <div className="px-5 pt-5 pb-0 flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className={`w-8 h-8 rounded-xl ${tc.iconColor} bg-current/10 flex items-center justify-center border border-current/20`}>
            <IconC size={16} />
          </div>
          <div>
            <p className="text-[10px] font-mono text-cyber-muted">{`Rank #${rank}`}</p>
            <p className="text-sm font-extrabold text-cyber-text font-mono capitalize">{algo.algorithm}</p>
          </div>
        </div>
        <div className="flex flex-col items-end gap-1.5">
          <Badge variant={tc.badge}>{tc.label}</Badge>
          <span className="text-[10px] font-mono text-cyber-muted">{algo.tier?.toUpperCase()}</span>
        </div>
      </div>

      {/* Score ring + bar */}
      <div className="px-5 py-4 flex items-center gap-5">
        <ScoreRing score={algo.score} grade={algo.grade} size={90} strokeWidth={7} color={color} />
        <div className="flex-1 space-y-2.5">
          {[
            { label: 'Security Score', value: algo.score, max: 100, color },
            { label: 'Anti-Crack',     value: Math.max(0, 100 - algo.crack_rate_pct), max: 100, color: algo.crack_rate_pct === 0 ? '#00ff88' : '#ff3366' },
          ].map(({ label, value, max, color: c }) => (
            <ProgressBar key={label} label={label} value={value} max={max} color={c} delay={delay + 0.4} />
          ))}
        </div>
      </div>

      {/* Property grid */}
      <div className="px-5 pb-4 grid grid-cols-2 gap-2">
        {[
          { label: 'Crack Rate', value: `${algo.crack_rate_pct}%`,  color: algo.crack_rate_pct === 0 ? 'text-cyber-green' : 'text-cyber-red' },
          { label: 'Salted',     value: algo.is_salted ? 'Yes' : 'No', color: algo.is_salted ? 'text-cyber-green' : 'text-cyber-red' },
          { label: 'Mem-Hard',   value: algo.is_memory_hard ? 'Yes' : 'No', color: algo.is_memory_hard ? 'text-cyber-green' : 'text-cyber-muted' },
          { label: 'Avg Time',   value: `${algo.avg_time_sec}s`,     color: 'text-cyber-cyan' },
        ].map(({ label, value, color: c }) => (
          <div key={label} className="flex justify-between items-center bg-cyber-card/40 rounded-lg px-3 py-1.5 border border-cyber-border/20">
            <span className="text-[10px] text-cyber-muted font-mono">{label}</span>
            <span className={`text-xs font-mono font-bold ${c}`}>{value}</span>
          </div>
        ))}
      </div>

      {/* Expand recommendations */}
      {algo.recommendations?.length > 0 && (
        <>
          <button
            onClick={() => setExpanded(p => !p)}
            className="w-full flex items-center justify-between px-5 py-2.5 border-t border-cyber-border/20
                       hover:bg-cyber-card/20 transition-colors text-xs font-mono text-cyber-muted"
          >
            <span>Recommendations ({algo.recommendations.length})</span>
            {expanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
          </button>
          <AnimatePresence>
            {expanded && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                className="overflow-hidden"
              >
                <div className="px-5 pb-4 space-y-1.5">
                  {algo.recommendations.map((r, i) => (
                    <div key={i} className="flex items-start gap-2 text-[11px] font-mono">
                      <span className={`${tc.iconColor} flex-shrink-0 mt-0.5`}>▸</span>
                      <span className="text-cyber-text/70 leading-snug">{r}</span>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </>
      )}
    </motion.div>
  )
}

export default function SecurityScorecard() {
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(true)
  const [view,    setView]    = useState('cards') // 'cards' | 'table'

  const load = () => {
    setLoading(true)
    getSecurityScore().then(r => setData(r.data)).catch(() => {}).finally(() => setLoading(false))
  }
  useEffect(load, [])

  const scores  = data?.algorithm_scores || []
  const sorted  = [...scores].sort((a, b) => b.score - a.score)
  const barData = sorted.map(a => ({
    name:  a.algorithm === 'salted_sha256' ? 'S-SHA256' : a.algorithm.toUpperCase(),
    algo:  a.algorithm,
    score: a.score,
  }))

  if (loading) return (
    <div className="flex items-center justify-center h-64 gap-3 text-cyber-muted">
      <RefreshCw size={22} className="animate-spin text-cyber-cyan" />
      <span className="font-mono text-sm">Computing security scores...</span>
    </div>
  )

  return (
    <div className="page-container">

      {/* ── Overall Banner ────────────────────────────────────── */}
      {data && (
        <motion.div initial={{ opacity: 0, y: -16 }} animate={{ opacity: 1, y: 0 }}
          className={`glass-card p-6 border ${data.overall_risk_level === 'LOW' ? 'border-cyber-green/30' : data.overall_risk_level === 'MEDIUM' ? 'border-yellow-400/30' : 'border-cyber-red/30'}`}>
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-6 items-center">
            <div className="flex items-center gap-4 sm:col-span-2">
              <Award size={36} className={
                data.overall_risk_level === 'LOW' ? 'text-cyber-green' :
                data.overall_risk_level === 'MEDIUM' ? 'text-yellow-400' : 'text-cyber-red'
              } />
              <div>
                <p className="text-[11px] font-mono text-cyber-muted uppercase tracking-widest">Overall System Risk</p>
                <p className={`text-3xl font-extrabold font-mono ${
                  data.overall_risk_level === 'LOW' ? 'text-cyber-green text-glow-green' :
                  data.overall_risk_level === 'MEDIUM' ? 'text-yellow-400 text-glow-yellow' : 'text-cyber-red text-glow-red'
                }`}>{data.overall_risk_level}</p>
                <p className="text-xs text-cyber-text/60 font-mono mt-1 max-w-sm">{data.summary}</p>
              </div>
            </div>
            <div className="text-center">
              <p className="text-[10px] font-mono text-cyber-muted mb-1">STRONGEST</p>
              <p className="text-xl font-extrabold font-mono text-cyber-green">{data.strongest_algorithm?.toUpperCase()}</p>
              <p className="text-[10px] font-mono text-cyber-green/50">Most secure</p>
            </div>
            <div className="text-center">
              <p className="text-[10px] font-mono text-cyber-muted mb-1">WEAKEST</p>
              <p className="text-xl font-extrabold font-mono text-cyber-red">{data.weakest_algorithm?.toUpperCase()}</p>
              <p className="text-[10px] font-mono text-cyber-red/50">Critical risk</p>
            </div>
          </div>
        </motion.div>
      )}

      {/* ── Controls ──────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5 p-1 bg-cyber-card/60 border border-cyber-border/40 rounded-xl">
          {[['cards', 'Score Cards'], ['table', 'Ranking Table']].map(([v, l]) => (
            <button key={v} onClick={() => setView(v)}
              className={view === v ? 'tab-btn-active' : 'tab-btn-inactive'}>{l}</button>
          ))}
        </div>
        <button onClick={load} className="btn-cyan">
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      {/* ── Cards View ────────────────────────────────────────── */}
      {view === 'cards' && (
        <>
          {/* Rank sections */}
          {['strong', 'moderate', 'weak'].map(tier => {
            const tierAlgos = sorted.filter(a =>
              tier === 'strong' ? a.score >= 70 : tier === 'moderate' ? a.score >= 40 && a.score < 70 : a.score < 40
            )
            if (!tierAlgos.length) return null
            const tc = TIER_CONFIG[tier]
            const IconC = tc.icon
            return (
              <div key={tier}>
                <div className="flex items-center gap-3 mb-4">
                  <IconC size={16} className={tc.iconColor} />
                  <span className={`text-sm font-bold font-mono ${tc.iconColor}`}>
                    {tier.toUpperCase()} ALGORITHMS
                  </span>
                  <div className="flex-1 h-px bg-gradient-to-r from-cyber-border/50 to-transparent" />
                  <Badge variant={tc.badge}>{tierAlgos.length} algo{tierAlgos.length > 1 ? 's' : ''}</Badge>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4 gap-4 mb-6">
                  {tierAlgos.map((a, i) => (
                    <AlgoCard key={a.algorithm} algo={a}
                      rank={sorted.findIndex(s => s.algorithm === a.algorithm) + 1}
                      delay={i * 0.08} />
                  ))}
                </div>
              </div>
            )
          })}

          {scores.length === 0 && (
            <div className="glass-card p-14 text-center">
              <Shield size={48} className="mx-auto mb-4 text-cyber-muted/20" />
              <p className="text-cyber-muted font-mono">No scorecard data — run security analysis first</p>
            </div>
          )}
        </>
      )}

      {/* ── Table View ────────────────────────────────────────── */}
      {view === 'table' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
          {/* Score bar chart */}
          <div className="glass-card p-5">
            <h3 className="text-sm font-bold text-cyber-text mb-4">Security Score Comparison</h3>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={barData} barSize={28} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} domain={[0, 100]} />
                <Tooltip content={<CyberTooltip />} />
                <Bar dataKey="score" name="Score" radius={[6, 6, 0, 0]}>
                  {barData.map((e, i) => (
                    <Cell key={i} fill={ALGO_COLORS[e.algo] || '#00f5ff'}
                      style={{ filter: `drop-shadow(0 0 6px ${ALGO_COLORS[e.algo] || '#00f5ff'}60)` }} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="glass-card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="cyber-table">
                <thead>
                  <tr>
                    <th>Rank</th>
                    <th>Algorithm</th>
                    <th>Grade</th>
                    <th>Score</th>
                    <th>Security Bar</th>
                    <th>Crack Rate</th>
                    <th>Salted</th>
                    <th>Mem Hard</th>
                    <th>Risk Level</th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((a, i) => (
                    <motion.tr key={a.algorithm}
                      initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.05 }}>
                      <td><span className="text-cyber-muted font-mono text-xs">#{i + 1}</span></td>
                      <td>
                        <div className="flex items-center gap-2">
                          <span className="w-2 h-2 rounded-full" style={{ background: ALGO_COLORS[a.algorithm] || '#fff' }} />
                          <span className="font-mono font-bold text-cyber-text text-xs">{a.algorithm}</span>
                        </div>
                      </td>
                      <td><GradeCircle grade={a.grade} score={a.score} size={40} /></td>
                      <td>
                        <span className="font-mono text-lg font-extrabold" style={{ color: ALGO_COLORS[a.algorithm] || '#fff' }}>
                          {a.score}
                        </span>
                      </td>
                      <td className="min-w-[120px]">
                        <ProgressBar value={a.score} max={100} color={ALGO_COLORS[a.algorithm] || '#00f5ff'} delay={i * 0.06} />
                      </td>
                      <td>
                        <span className={`font-mono text-xs font-bold ${a.crack_rate_pct === 0 ? 'text-cyber-green' : a.crack_rate_pct < 50 ? 'text-yellow-400' : 'text-cyber-red'}`}>
                          {a.crack_rate_pct}%
                        </span>
                      </td>
                      <td><Badge variant={a.is_salted ? 'green' : 'red'}>{a.is_salted ? 'Yes' : 'No'}</Badge></td>
                      <td><Badge variant={a.is_memory_hard ? 'green' : 'gray'}>{a.is_memory_hard ? 'Yes' : 'No'}</Badge></td>
                      <td>
                        <Badge variant={a.score >= 70 ? 'green' : a.score >= 40 ? 'yellow' : 'red'}>
                          {a.score >= 70 ? 'LOW' : a.score >= 40 ? 'MEDIUM' : 'HIGH'}
                        </Badge>
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </motion.div>
      )}

      {/* ── Global Recommendations ────────────────────────────── */}
      {data?.recommendations?.length > 0 && (
        <motion.div initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }} className="card-cyan p-5">
          <h3 className="text-sm font-bold text-cyber-text mb-4 flex items-center gap-2">
            <Award size={15} className="text-cyber-cyan" /> Global Security Recommendations
          </h3>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            {data.recommendations.map((r, i) => (
              <motion.div key={i}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.07 }}
                className="flex items-start gap-3 bg-cyber-card/40 rounded-xl p-3 border border-cyber-cyan/15"
              >
                <span className="text-cyber-cyan text-xs flex-shrink-0 mt-0.5">▸</span>
                <span className="text-xs text-cyber-text/80 font-mono leading-relaxed">{r}</span>
              </motion.div>
            ))}
          </div>
        </motion.div>
      )}
    </div>
  )
}
