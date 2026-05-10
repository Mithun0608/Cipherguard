import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  Cell, LineChart, Line, AreaChart, Area, ScatterChart, Scatter
} from 'recharts'
import {
  Search, Download, RefreshCw, Filter, ChevronLeft,
  ChevronRight, BookOpen, Zap, Layers, Dna, TrendingUp,
  Clock, Target, AlertTriangle, Shield, BarChart2
} from 'lucide-react'
import { Badge, AttackBadge, CrackStatus, SectionHeader } from '../components/ui/Badges'
import { CyberTooltip, ProgressBar } from '../components/ui/Charts'
import { getAttackResults } from '../services/api'

const ATTACK_TYPES = ['all', 'dictionary', 'brute_force', 'rainbow_table', 'hybrid']

// ── Per-type section configuration ────────────────────────────────────────
const SECTION_CONFIG = {
  dictionary: {
    title: 'Dictionary Attack',
    icon: BookOpen,
    color: 'cyan',
    accentColor: '#00f5ff',
    desc: 'Wordlist-based hash comparison — exploits common passwords',
    columns: ['id', 'algorithm', 'target_count', 'cracked_count', 'success_rate_pct', 'attempts_per_sec', 'total_time_sec', 'stopped_early'],
  },
  brute_force: {
    title: 'Brute Force Attack',
    icon: Zap,
    color: 'purple',
    accentColor: '#8b5cf6',
    desc: 'Exhaustive combination enumeration — resource intensive',
    columns: ['id', 'algorithm', 'target_count', 'cracked_count', 'success_rate_pct', 'total_attempts', 'attempts_per_sec', 'total_time_sec'],
  },
  rainbow_table: {
    title: 'Rainbow Table Attack',
    icon: Layers,
    color: 'yellow',
    accentColor: '#ffd700',
    desc: 'Precomputed hash lookup — defeated by salting',
    columns: ['id', 'algorithm', 'target_count', 'cracked_count', 'success_rate_pct', 'avg_crack_time_ms', 'total_time_sec', 'stopped_early'],
  },
  hybrid: {
    title: 'Hybrid Attack',
    icon: Dna,
    color: 'orange',
    accentColor: '#ff8c00',
    desc: 'Dictionary + rule mutations — catches common variations',
    columns: ['id', 'algorithm', 'target_count', 'cracked_count', 'success_rate_pct', 'wordlist_size', 'attempts_per_sec', 'total_time_sec'],
  },
}

const COL_LABELS = {
  id:               { label: '#',           render: r => <span className="text-cyber-muted text-xs font-mono">#{r.id}</span> },
  algorithm:        { label: 'Algorithm',   render: r => <span className="font-mono text-xs font-semibold text-cyber-text">{r.algorithm}</span> },
  target_count:     { label: 'Targets',     render: r => <span className="font-mono text-xs">{r.target_count}</span> },
  cracked_count:    { label: 'Cracked',     render: r => <span className={`font-mono text-xs font-bold ${r.cracked_count > 0 ? 'text-cyber-red' : 'text-cyber-green'}`}>{r.cracked_count}</span> },
  success_rate_pct: { label: 'Success %',   render: r => (
    <div className="flex items-center gap-2">
      <div className="progress-bar w-14">
        <div className="progress-fill" style={{
          width: `${r.success_rate_pct}%`,
          background: r.success_rate_pct > 50 ? '#ff3366' : r.success_rate_pct > 0 ? '#ffd700' : '#00ff88'
        }} />
      </div>
      <span className={`text-xs font-mono font-bold ${r.success_rate_pct > 50 ? 'text-cyber-red' : r.success_rate_pct > 0 ? 'text-yellow-400' : 'text-cyber-green'}`}>
        {r.success_rate_pct}%
      </span>
    </div>
  )},
  attempts_per_sec: { label: 'Speed',       render: r => <span className="font-mono text-xs text-cyber-cyan">{r.attempts_per_sec?.toLocaleString()}/s</span> },
  total_time_sec:   { label: 'Duration',    render: r => <span className="font-mono text-xs text-cyber-muted">{r.total_time_sec?.toFixed(3)}s</span> },
  stopped_early:    { label: 'Status',      render: r => r.stopped_early ? <Badge variant="yellow">PARTIAL</Badge> : <Badge variant="green">COMPLETE</Badge> },
  total_attempts:   { label: 'Attempts',    render: r => <span className="font-mono text-xs">{r.total_attempts?.toLocaleString() || '—'}</span> },
  avg_crack_time_ms:{ label: 'Avg Crack',   render: r => <span className="font-mono text-xs text-cyber-yellow">{r.avg_crack_time_ms?.toFixed(4) || '—'}ms</span> },
  wordlist_size:    { label: 'Candidates',  render: r => <span className="font-mono text-xs text-cyber-orange">{r.wordlist_size?.toLocaleString() || '—'}</span> },
}

const PER_PAGE = 7

function AttackSection({ type, data, config }) {
  const [search,  setSearch]  = useState('')
  const [page,    setPage]    = useState(0)
  const [sortKey, setSortKey] = useState('id')
  const [sortDir, setSortDir] = useState('desc')
  const { title, icon: Icon, color, accentColor, desc, columns } = config

  const borderMap = { cyan: 'border-neon-cyan', purple: 'border-neon-purple', yellow: 'border-yellow-400/30', orange: 'border-orange-400/30' }
  const cardMap   = { cyan: 'card-cyan', purple: 'card-purple', yellow: 'card-yellow', orange: 'glass-card border border-orange-400/20' }
  const bgMap     = { cyan: 'bg-cyber-cyan/10', purple: 'bg-cyber-purple/10', yellow: 'bg-yellow-400/10', orange: 'bg-orange-400/10' }
  const textMap   = { cyan: 'text-cyber-cyan', purple: 'text-cyber-purple', yellow: 'text-yellow-400', orange: 'text-orange-400' }

  const filtered = data.filter(r =>
    r.algorithm?.toLowerCase().includes(search.toLowerCase()) ||
    r.attack_type?.includes(search.toLowerCase())
  )
  const sorted = [...filtered].sort((a, b) => {
    const av = a[sortKey] ?? 0, bv = b[sortKey] ?? 0
    return sortDir === 'asc' ? (av > bv ? 1 : -1) : (av < bv ? 1 : -1)
  })
  const pages  = Math.ceil(sorted.length / PER_PAGE)
  const paged  = sorted.slice(page * PER_PAGE, page * PER_PAGE + PER_PAGE)

  const exportCSV = () => {
    if (!data.length) return
    const h = Object.keys(data[0]).join(',')
    const rows = data.map(r => Object.values(r).join(','))
    const blob = new Blob([[h, ...rows].join('\n')], { type: 'text/csv' })
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
    a.download = `${type}_results.csv`; a.click()
  }

  const toggleSort = (key) => {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortKey(key); setSortDir('desc') }
  }

  const chartData = data.map(r => ({
    name:  r.algorithm === 'salted_sha256' ? 'S-SHA256' : r.algorithm?.toUpperCase(),
    rate:  r.success_rate_pct,
    speed: Math.min(r.attempts_per_sec / 1000, 999),
    time:  r.total_time_sec,
  }))

  const avgRate = data.length
    ? (data.reduce((s, r) => s + r.success_rate_pct, 0) / data.length).toFixed(1) : '0'
  const maxCracked = Math.max(...data.map(r => r.cracked_count), 0)

  return (
    <motion.div
      initial={{ opacity: 0, y: 24 }}
      animate={{ opacity: 1, y: 0 }}
      className={`${cardMap[color]} overflow-hidden`}
    >
      {/* Header */}
      <div className={`px-5 py-4 border-b border-cyber-border/20 bg-gradient-to-r from-transparent`}>
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <div className={`w-9 h-9 rounded-xl ${bgMap[color]} border border-current/20 flex items-center justify-center ${textMap[color]}`}>
              <Icon size={17} />
            </div>
            <div>
              <h3 className="text-sm font-bold text-cyber-text">{title}</h3>
              <p className="text-[10px] text-cyber-muted font-mono">{desc}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-2 bg-cyber-card/60 border border-cyber-border/40 rounded-xl px-3 py-1.5">
              <Search size={12} className="text-cyber-muted" />
              <input value={search} onChange={e => { setSearch(e.target.value); setPage(0) }}
                placeholder="Filter..." className="bg-transparent text-xs text-cyber-text outline-none w-20 font-mono placeholder:text-cyber-muted/30" />
            </div>
            <button onClick={exportCSV} disabled={!data.length} className={`btn-${color} text-xs py-1.5`}>
              <Download size={12} /> CSV
            </button>
            <Badge variant={color}>{data.length} runs</Badge>
          </div>
        </div>
      </div>

      {/* Analytics + Table */}
      <div className="grid grid-cols-1 lg:grid-cols-4 divide-y lg:divide-y-0 lg:divide-x divide-cyber-border/20">

        {/* Analytics sidebar */}
        <div className="p-5 space-y-5">
          {/* Mini stats */}
          <div className="space-y-3">
            {[
              { label: 'Total Runs',   value: data.length,     color: textMap[color] },
              { label: 'Avg Crack %',  value: `${avgRate}%`,  color: avgRate > 50 ? 'text-cyber-red' : avgRate > 0 ? 'text-yellow-400' : 'text-cyber-green' },
              { label: 'Max Cracked',  value: maxCracked,      color: maxCracked > 0 ? 'text-cyber-red' : 'text-cyber-green' },
            ].map(({ label, value, color: c }) => (
              <div key={label} className="flex justify-between items-center py-1.5 border-b border-cyber-border/20">
                <span className="text-xs text-cyber-muted font-mono">{label}</span>
                <span className={`text-sm font-mono font-bold ${c}`}>{value}</span>
              </div>
            ))}
          </div>

          {/* Chart */}
          <div>
            <p className="text-[10px] font-mono text-cyber-muted mb-2 uppercase tracking-wide">Success Rate</p>
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={130}>
                <BarChart data={chartData} barSize={14} margin={{ top: 2, right: 2, left: -25, bottom: 0 }}>
                  <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 8, fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 8 }} axisLine={false} tickLine={false} domain={[0, 100]} />
                  <Tooltip content={<CyberTooltip />} />
                  <Bar dataKey="rate" name="Crack %" radius={[3, 3, 0, 0]}>
                    {chartData.map((_, i) => (
                      <Cell key={i} fill={accentColor} style={{ filter: `drop-shadow(0 0 4px ${accentColor}80)` }} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-28 flex items-center justify-center text-cyber-muted/30 text-xs font-mono">No data</div>
            )}
          </div>

          {/* Time chart */}
          {data.length > 0 && (
            <div>
              <p className="text-[10px] font-mono text-cyber-muted mb-2 uppercase tracking-wide">Duration (sec)</p>
              <ResponsiveContainer width="100%" height={80}>
                <AreaChart data={chartData} margin={{ top: 2, right: 2, left: -25, bottom: 0 }}>
                  <defs>
                    <linearGradient id={`grad-${type}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={accentColor} stopOpacity={0.3} />
                      <stop offset="95%" stopColor={accentColor} stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="name" hide />
                  <YAxis hide />
                  <Tooltip content={<CyberTooltip />} />
                  <Area type="monotone" dataKey="time" stroke={accentColor} strokeWidth={1.5}
                    fill={`url(#grad-${type})`} name="Duration (s)" dot={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Table */}
        <div className="lg:col-span-3 overflow-x-auto">
          {paged.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-3 text-cyber-muted">
              <Icon size={32} className="opacity-20" />
              <p className="text-sm font-mono">No {title} data</p>
              <p className="text-xs font-mono opacity-60">Run experiments to generate results</p>
            </div>
          ) : (
            <>
              <table className="cyber-table">
                <thead>
                  <tr>
                    {columns.map(k => (
                      <th key={k} onClick={() => toggleSort(k)}
                        className="cursor-pointer hover:text-cyber-cyan/90 transition-colors select-none">
                        <div className="flex items-center gap-1">
                          {COL_LABELS[k]?.label || k}
                          {sortKey === k && (
                            <span className={`text-[10px] ${textMap[color]}`}>{sortDir === 'asc' ? '↑' : '↓'}</span>
                          )}
                        </div>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {paged.map((r, i) => (
                    <motion.tr key={r.id || i}
                      initial={{ opacity: 0, x: 8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.04 }}
                    >
                      {columns.map(k => (
                        <td key={k}>{COL_LABELS[k]?.render(r) ?? <span className="font-mono text-xs text-cyber-muted">{r[k] ?? '—'}</span>}</td>
                      ))}
                    </motion.tr>
                  ))}
                </tbody>
              </table>

              {/* Pagination */}
              {pages > 1 && (
                <div className="flex items-center justify-between px-5 py-3 border-t border-cyber-border/20">
                  <span className="text-xs font-mono text-cyber-muted">{sorted.length} results</span>
                  <div className="flex items-center gap-1">
                    <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
                      className="p-1.5 rounded-lg text-cyber-muted hover:text-cyber-cyan disabled:opacity-30 transition-colors">
                      <ChevronLeft size={14} />
                    </button>
                    {Array.from({ length: Math.min(pages, 8) }).map((_, p) => (
                      <button key={p} onClick={() => setPage(p)}
                        className={`w-7 h-7 rounded-lg text-xs font-mono transition-all ${
                          page === p
                            ? `${bgMap[color]} ${textMap[color]} border border-current/30 font-bold`
                            : 'text-cyber-muted hover:text-cyber-text'
                        }`}>
                        {p + 1}
                      </button>
                    ))}
                    <button onClick={() => setPage(p => Math.min(pages - 1, p + 1))} disabled={page >= pages - 1}
                      className="p-1.5 rounded-lg text-cyber-muted hover:text-cyber-cyan disabled:opacity-30 transition-colors">
                      <ChevronRight size={14} />
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </motion.div>
  )
}

export default function AttackAnalysis() {
  const [results, setResults] = useState([])
  const [filter,  setFilter]  = useState('all')
  const [loading, setLoading] = useState(true)

  const load = () => {
    setLoading(true)
    getAttackResults({ limit: 300 })
      .then(r => setResults(r.data.results || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }
  useEffect(load, [])

  const byType = (t) => results.filter(r => r.attack_type === t)

  const overallStats = [
    { label: 'Total Runs',    value: results.length,                              color: 'cyan'   },
    { label: 'Dict Attacks',  value: byType('dictionary').length,                  color: 'cyan'   },
    { label: 'Brute Force',   value: byType('brute_force').length,                 color: 'purple' },
    { label: 'Rainbow Table', value: byType('rainbow_table').length,               color: 'yellow' },
    { label: 'Hybrid',        value: byType('hybrid').length,                      color: 'orange' },
    { label: 'Avg Crack %',
      value: results.length ? `${(results.reduce((s,r) => s + r.success_rate_pct, 0) / results.length).toFixed(1)}%` : '—',
      color: 'red' },
  ]

  const colorMap = { cyan: 'text-cyber-cyan border-cyber-cyan/20', purple: 'text-cyber-purple border-cyber-purple/20', yellow: 'text-yellow-400 border-yellow-400/20', orange: 'text-orange-400 border-orange-400/20', red: 'text-cyber-red border-cyber-red/20' }

  return (
    <div className="page-container">

      {/* ── Summary Strip ─────────────────────────────────────── */}
      <div className="grid grid-cols-3 sm:grid-cols-6 gap-3">
        {overallStats.map(({ label, value, color }) => (
          <motion.div key={label}
            initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
            className={`glass-card px-4 py-3 border ${colorMap[color]}`}>
            <p className={`text-xl font-extrabold font-mono ${colorMap[color].split(' ')[0]}`}>{loading ? '—' : value}</p>
            <p className="text-[10px] text-cyber-muted mt-0.5 font-medium">{label}</p>
          </motion.div>
        ))}
      </div>

      {/* ── Filter + Refresh ──────────────────────────────────── */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-1.5 p-1 bg-cyber-card/60 border border-cyber-border/40 rounded-xl">
          {ATTACK_TYPES.map(t => (
            <button key={t} onClick={() => setFilter(t)}
              className={filter === t ? 'tab-btn-active' : 'tab-btn-inactive'}>
              {t === 'all' ? 'All Attacks' : t.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
            </button>
          ))}
        </div>
        <button onClick={load} className="btn-cyan ml-auto">
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {/* ── Attack Sections ───────────────────────────────────── */}
      {(filter === 'all' || filter === 'dictionary') && (
        <AttackSection type="dictionary" data={byType('dictionary')} config={SECTION_CONFIG.dictionary} />
      )}
      {(filter === 'all' || filter === 'brute_force') && (
        <AttackSection type="brute_force" data={byType('brute_force')} config={SECTION_CONFIG.brute_force} />
      )}
      {(filter === 'all' || filter === 'rainbow_table') && (
        <AttackSection type="rainbow_table" data={byType('rainbow_table')} config={SECTION_CONFIG.rainbow_table} />
      )}
      {(filter === 'all' || filter === 'hybrid') && (
        <AttackSection type="hybrid" data={byType('hybrid')} config={SECTION_CONFIG.hybrid} />
      )}

      {!loading && results.length === 0 && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
          className="glass-card p-14 text-center border border-cyber-border/20">
          <BarChart2 size={48} className="mx-auto mb-4 text-cyber-muted/20" />
          <p className="text-lg font-bold text-cyber-text mb-2">No Attack Data</p>
          <p className="text-sm text-cyber-muted font-mono">Run experiments first to see per-attack analysis</p>
        </motion.div>
      )}
    </div>
  )
}
