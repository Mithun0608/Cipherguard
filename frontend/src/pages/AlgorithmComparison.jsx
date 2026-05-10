import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  Cell, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  LineChart, Line, AreaChart, Area, Legend
} from 'recharts'
import {
  TrendingUp, TrendingDown, RefreshCw, GitCompare,
  Lock, Unlock, Cpu, Zap, Shield, Award, BarChart2
} from 'lucide-react'
import { Badge, RiskBadge, GradeCircle } from '../components/ui/Badges'
import { CyberTooltip, ProgressBar } from '../components/ui/Charts'
import { getSecurityScore } from '../services/api'

const ALGO_COLORS = {
  plaintext: '#ff3366', md5: '#ff3366', sha1: '#ff8c00',
  sha256: '#ffd700', salted_sha256: '#00f5ff', bcrypt: '#8b5cf6', argon2id: '#00ff88',
}

const ALGO_META = {
  plaintext:     { saltSupport: false, rainbowResist: 'None',    gpuResist: 'None',    category: 'Legacy' },
  md5:           { saltSupport: false, rainbowResist: 'None',    gpuResist: 'None',    category: 'Broken' },
  sha1:          { saltSupport: false, rainbowResist: 'Low',     gpuResist: 'Low',     category: 'Deprecated' },
  sha256:        { saltSupport: false, rainbowResist: 'Low',     gpuResist: 'Low',     category: 'Hash-Only' },
  salted_sha256: { saltSupport: true,  rainbowResist: 'Medium',  gpuResist: 'Low',     category: 'Salted' },
  bcrypt:        { saltSupport: true,  rainbowResist: 'High',    gpuResist: 'Medium',  category: 'Password KDF' },
  argon2id:      { saltSupport: true,  rainbowResist: 'Maximum', gpuResist: 'Maximum', category: 'Modern KDF' },
}

const RESIST_SCORE = { None: 0, Low: 25, Medium: 55, High: 80, Maximum: 100 }

const COMPARISON_PROPS = [
  { key: 'score',          label: 'Security Score', fmt: v => `${v}/100` },
  { key: 'grade',          label: 'Grade',          fmt: v => v },
  { key: 'tier',           label: 'Tier',           fmt: v => v?.toUpperCase() },
  { key: 'crack_rate_pct', label: 'Crack Rate',     fmt: v => `${v}%` },
  { key: 'is_salted',      label: 'Salted',         fmt: v => v ? '✓ Yes' : '✗ No' },
  { key: 'is_memory_hard', label: 'Memory Hard',    fmt: v => v ? '✓ Yes' : '✗ No' },
  { key: 'avg_time_sec',   label: 'Avg Time',       fmt: v => `${v}s` },
]

function PropCell({ propKey, value }) {
  let color = 'text-cyber-cyan'
  if (propKey === 'score')          color = value >= 70 ? 'text-cyber-green' : value >= 40 ? 'text-yellow-400' : 'text-cyber-red'
  if (propKey === 'crack_rate_pct') color = value === 0 ? 'text-cyber-green' : value < 50 ? 'text-yellow-400' : 'text-cyber-red'
  if (propKey === 'is_salted' || propKey === 'is_memory_hard')
    color = value ? 'text-cyber-green' : 'text-cyber-red'
  if (propKey === 'grade')          color = { A: 'text-cyber-green', B: 'text-cyber-cyan', C: 'text-yellow-400', D: 'text-orange-400', F: 'text-cyber-red' }[value] || 'text-cyber-muted'

  const fmt = COMPARISON_PROPS.find(p => p.key === propKey)?.fmt
  const display = fmt ? fmt(value) : String(value ?? '—')

  return <span className={`font-mono text-xs font-semibold ${color}`}>{display}</span>
}

export default function AlgorithmComparison() {
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(true)

  const load = () => {
    setLoading(true)
    getSecurityScore().then(r => setData(r.data)).catch(() => {}).finally(() => setLoading(false))
  }
  useEffect(load, [])

  const scores = data?.algorithm_scores || []
  const sorted = [...scores].sort((a, b) => b.score - a.score)

  const barData = scores.map(a => ({
    name: a.algorithm === 'salted_sha256' ? 'S-SHA256' : a.algorithm.toUpperCase(),
    algo: a.algorithm, score: a.score, crack: a.crack_rate_pct,
  }))

  const radarData = ['Score', 'Anti-Crack', 'Salted', 'MemHard', 'RainbowR'].map(metric => {
    const entry = { metric }
    scores.forEach(a => {
      const name = a.algorithm === 'salted_sha256' ? 'S-SHA256' : a.algorithm
      if (metric === 'Score')    entry[name] = a.score
      if (metric === 'Anti-Crack') entry[name] = Math.max(0, 100 - a.crack_rate_pct)
      if (metric === 'Salted')   entry[name] = a.is_salted ? 100 : 0
      if (metric === 'MemHard')  entry[name] = a.is_memory_hard ? 100 : 0
      if (metric === 'RainbowR') entry[name] = RESIST_SCORE[ALGO_META[a.algorithm]?.rainbowResist] || 0
    })
    return entry
  })

  const lineData = sorted.map((a, i) => ({
    rank:  i + 1,
    name:  a.algorithm === 'salted_sha256' ? 'S-SHA256' : a.algorithm,
    score: a.score,
    algo:  a.algorithm,
  }))

  if (loading) return (
    <div className="flex items-center justify-center h-64 gap-3 text-cyber-muted">
      <RefreshCw size={22} className="animate-spin text-cyber-cyan" />
      <span className="font-mono">Loading comparison data...</span>
    </div>
  )

  return (
    <div className="page-container">

      {/* ── Summary Banner ────────────────────────────────────── */}
      {data && (
        <motion.div initial={{ opacity: 0, y: -16 }} animate={{ opacity: 1, y: 0 }}
          className="glass-card p-5 border border-cyber-cyan/20">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-cyber-green/10 border border-cyber-green/30 flex items-center justify-center">
                <TrendingUp size={18} className="text-cyber-green" />
              </div>
              <div>
                <p className="text-[10px] text-cyber-muted font-mono">STRONGEST</p>
                <p className="text-sm font-extrabold text-cyber-green font-mono">{data.strongest_algorithm?.toUpperCase()}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-cyber-red/10 border border-cyber-red/30 flex items-center justify-center">
                <TrendingDown size={18} className="text-cyber-red" />
              </div>
              <div>
                <p className="text-[10px] text-cyber-muted font-mono">WEAKEST</p>
                <p className="text-sm font-extrabold text-cyber-red font-mono">{data.weakest_algorithm?.toUpperCase()}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-cyber-cyan/10 border border-cyber-cyan/30 flex items-center justify-center">
                <BarChart2 size={18} className="text-cyber-cyan" />
              </div>
              <div>
                <p className="text-[10px] text-cyber-muted font-mono">ALGORITHMS</p>
                <p className="text-sm font-extrabold text-cyber-cyan font-mono">{scores.length} evaluated</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-cyber-purple/10 border border-cyber-purple/30 flex items-center justify-center">
                <Shield size={18} className="text-cyber-purple" />
              </div>
              <div>
                <p className="text-[10px] text-cyber-muted font-mono">OVERALL RISK</p>
                <RiskBadge level={data.overall_risk_level} />
              </div>
            </div>
          </div>
        </motion.div>
      )}

      {/* ── Charts Grid ───────────────────────────────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">

        {/* Score Bar */}
        <motion.div initial={{ opacity: 0, x: -24 }} animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.1 }} className="glass-card p-5">
          <h3 className="text-sm font-bold text-cyber-text mb-1 flex items-center gap-2">
            <Award size={14} className="text-cyber-cyan" /> Security Score Ranking
          </h3>
          <p className="text-xs text-cyber-muted font-mono mb-4">Higher = more resistant to attacks</p>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={barData} barSize={26} margin={{ top: 4, right: 4, left: -22, bottom: 0 }}>
              <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} domain={[0, 100]} />
              <Tooltip content={<CyberTooltip />} />
              <Bar dataKey="score" name="Score" radius={[6, 6, 0, 0]}>
                {barData.map((e, i) => (
                  <Cell key={i} fill={ALGO_COLORS[e.algo] || '#00f5ff'}
                    style={{ filter: `drop-shadow(0 0 5px ${ALGO_COLORS[e.algo] || '#00f5ff'}60)` }} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </motion.div>

        {/* Crack Rate Bar */}
        <motion.div initial={{ opacity: 0, x: 24 }} animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.1 }} className="glass-card p-5">
          <h3 className="text-sm font-bold text-cyber-text mb-1 flex items-center gap-2">
            <Zap size={14} className="text-cyber-red" /> Avg Crack Rate (%)
          </h3>
          <p className="text-xs text-cyber-muted font-mono mb-4">Lower = more resistant to attacks</p>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={barData} barSize={26} margin={{ top: 4, right: 4, left: -22, bottom: 0 }}>
              <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} domain={[0, 100]} />
              <Tooltip content={<CyberTooltip />} />
              <Bar dataKey="crack" name="Crack %" radius={[6, 6, 0, 0]}>
                {barData.map((e, i) => (
                  <Cell key={i} fill={e.crack > 50 ? '#ff3366' : e.crack > 0 ? '#ffd700' : '#00ff88'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </motion.div>

        {/* Radar */}
        <motion.div initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }} className="glass-card p-5">
          <h3 className="text-sm font-bold text-cyber-text mb-1 flex items-center gap-2">
            <GitCompare size={14} className="text-cyber-purple" /> Multi-Dimension Radar
          </h3>
          <p className="text-xs text-cyber-muted font-mono mb-4">Security attributes across 5 dimensions</p>
          <ResponsiveContainer width="100%" height={240}>
            <RadarChart data={radarData} margin={{ top: 10, right: 30, left: 30, bottom: 10 }}>
              <PolarGrid stroke="rgba(30,58,95,0.5)" />
              <PolarAngleAxis dataKey="metric" tick={{ fill: '#64748b', fontSize: 9, fontFamily: 'monospace' }} />
              <PolarRadiusAxis angle={90} domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 8 }} />
              {scores.slice(0, 4).map(a => (
                <Radar key={a.algorithm}
                  name={a.algorithm === 'salted_sha256' ? 'S-SHA256' : a.algorithm}
                  dataKey={a.algorithm === 'salted_sha256' ? 'S-SHA256' : a.algorithm}
                  stroke={ALGO_COLORS[a.algorithm]} strokeWidth={1.5}
                  fill={ALGO_COLORS[a.algorithm]} fillOpacity={0.1}
                />
              ))}
              <Tooltip content={<CyberTooltip />} />
              <Legend iconType="circle" iconSize={8}
                wrapperStyle={{ fontSize: '10px', fontFamily: 'monospace', color: '#64748b' }} />
            </RadarChart>
          </ResponsiveContainer>
        </motion.div>

        {/* Score trend line */}
        <motion.div initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }} className="glass-card p-5">
          <h3 className="text-sm font-bold text-cyber-text mb-1 flex items-center gap-2">
            <TrendingUp size={14} className="text-cyber-green" /> Security Ranking Curve
          </h3>
          <p className="text-xs text-cyber-muted font-mono mb-4">Score progression from weakest to strongest</p>
          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={lineData} margin={{ top: 4, right: 4, left: -22, bottom: 0 }}>
              <defs>
                <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#00ff88" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#00ff88" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 9, fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} domain={[0, 100]} />
              <Tooltip content={<CyberTooltip />} />
              <Area type="monotone" dataKey="score" stroke="#00ff88" strokeWidth={2}
                fill="url(#scoreGrad)" name="Score"
                dot={entry => (
                  <circle cx={entry.cx} cy={entry.cy} r={4}
                    fill={ALGO_COLORS[lineData[entry.index]?.algo] || '#00ff88'}
                    stroke="none"
                    style={{ filter: `drop-shadow(0 0 4px ${ALGO_COLORS[lineData[entry.index]?.algo] || '#00ff88'})` }}
                  />
                )}
              />
            </AreaChart>
          </ResponsiveContainer>
        </motion.div>
      </div>

      {/* ── Full Comparison Table ─────────────────────────────── */}
      <motion.div initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }} className="glass-card overflow-hidden">
        <div className="px-5 py-4 border-b border-cyber-border/30 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-cyber-text flex items-center gap-2">
              <GitCompare size={14} className="text-cyber-cyan" /> Algorithm Property Matrix
            </h3>
            <p className="text-xs text-cyber-muted font-mono">Complete side-by-side security comparison</p>
          </div>
          <Badge variant="cyan">{scores.length} algorithms</Badge>
        </div>
        <div className="overflow-x-auto">
          <table className="cyber-table">
            <thead>
              <tr>
                <th className="sticky left-0 bg-cyber-panel z-10 min-w-[130px]">Algorithm</th>
                {COMPARISON_PROPS.map(p => <th key={p.key}>{p.label}</th>)}
                <th>Salt Support</th>
                <th>Rainbow Resist</th>
                <th>Risk Level</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((a, i) => {
                const meta = ALGO_META[a.algorithm] || {}
                return (
                  <motion.tr key={a.algorithm}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: i * 0.06 }}
                  >
                    <td className="sticky left-0 bg-cyber-panel z-10">
                      <div className="flex items-center gap-2">
                        <GradeCircle grade={a.grade} score={a.score} size={40} />
                        <div>
                          <p className="font-mono font-bold text-cyber-text text-xs">{a.algorithm}</p>
                          <p className="text-[10px] text-cyber-muted font-mono">{meta.category}</p>
                        </div>
                      </div>
                    </td>
                    {COMPARISON_PROPS.map(p => (
                      <td key={p.key}><PropCell propKey={p.key} value={a[p.key]} /></td>
                    ))}
                    <td>
                      {meta.saltSupport
                        ? <Badge variant="green"><Lock size={9} /> Yes</Badge>
                        : <Badge variant="red"><Unlock size={9} /> No</Badge>
                      }
                    </td>
                    <td>
                      <Badge variant={
                        meta.rainbowResist === 'Maximum' ? 'green'
                        : meta.rainbowResist === 'High' ? 'cyan'
                        : meta.rainbowResist === 'Medium' ? 'yellow'
                        : 'red'
                      }>{meta.rainbowResist}</Badge>
                    </td>
                    <td>
                      <Badge variant={a.score >= 70 ? 'green' : a.score >= 40 ? 'yellow' : 'red'}>
                        {a.score >= 70 ? 'LOW RISK' : a.score >= 40 ? 'MEDIUM' : 'HIGH RISK'}
                      </Badge>
                    </td>
                  </motion.tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </motion.div>

      {/* ── Recommendations ───────────────────────────────────── */}
      {data?.recommendations?.length > 0 && (
        <motion.div initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }} className="card-yellow p-5">
          <h3 className="text-sm font-bold text-cyber-text mb-4 flex items-center gap-2">
            <Shield size={14} className="text-yellow-400" /> Security Recommendations
          </h3>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            {data.recommendations.map((r, i) => (
              <motion.div key={i}
                initial={{ opacity: 0, x: -12 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.07 }}
                className="flex items-start gap-3 bg-cyber-card/40 rounded-xl p-3 border border-cyber-border/30"
              >
                <span className="text-yellow-400 font-mono text-xs mt-0.5 flex-shrink-0">▸</span>
                <p className="text-xs text-cyber-text/80 font-mono leading-relaxed">{r}</p>
              </motion.div>
            ))}
          </div>
        </motion.div>
      )}
    </div>
  )
}
