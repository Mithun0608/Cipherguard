import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  FileText, Search, Download, RefreshCw, ChevronDown,
  ChevronRight, Filter, Clock, Zap, Database, Shield,
  AlertCircle, CheckCircle, XCircle, Activity, BookOpen
} from 'lucide-react'
import { Badge, AttackBadge } from '../components/ui/Badges'
import { getAttackLogs, getAttackResults } from '../services/api'

const ATTACK_COLORS = {
  dictionary:    { badge: 'cyan',   text: 'text-cyber-cyan'   },
  brute_force:   { badge: 'purple', text: 'text-cyber-purple' },
  rainbow_table: { badge: 'yellow', text: 'text-yellow-400'   },
  hybrid:        { badge: 'orange', text: 'text-orange-400'   },
}

function LogRow({ log, index }) {
  const [open, setOpen] = useState(false)
  const r = log.results || {}
  const ac = ATTACK_COLORS[log.attack_type] || { badge: 'gray', text: 'text-cyber-muted' }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.04 }}
      className="border border-cyber-border/25 rounded-xl overflow-hidden mb-2 hover:border-cyber-border/50 transition-colors"
    >
      <button
        onClick={() => setOpen(p => !p)}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-cyber-cyan/3 transition-colors text-left"
      >
        <motion.div animate={{ rotate: open ? 90 : 0 }} transition={{ duration: 0.2 }}>
          <ChevronRight size={13} className={`flex-shrink-0 ${open ? 'text-cyber-cyan' : 'text-cyber-muted'}`} />
        </motion.div>

        <span className="text-[10px] text-cyber-muted font-mono flex-shrink-0 w-32 hidden sm:block">
          {log.timestamp?.slice(0, 19)?.replace('T', ' ')}
        </span>

        <Badge variant={ac.badge}>{log.attack_type?.replace(/_/g, ' ')}</Badge>

        <span className={`text-xs font-mono font-bold flex-shrink-0 ${r.cracked_count > 0 ? 'text-cyber-red' : 'text-cyber-green'}`}>
          {log.algorithm?.toUpperCase()}
        </span>

        <span className="text-xs font-mono text-cyber-text flex-1 text-left">
          <span className={r.cracked_count > 0 ? 'text-cyber-red font-bold' : 'text-cyber-green'}>{r.cracked_count}</span>
          <span className="text-cyber-muted">/{r.target_count}</span>
          <span className="text-cyber-muted ml-1">cracked</span>
          <span className="text-cyber-cyan ml-2">({r.success_rate_pct?.toFixed(1)}%)</span>
        </span>

        <span className="text-xs font-mono text-cyber-muted flex-shrink-0 hidden md:block">
          {r.total_time_sec?.toFixed(3)}s
        </span>

        {r.cracked_count > 0
          ? <AlertCircle size={14} className="text-cyber-red flex-shrink-0" />
          : <CheckCircle size={14} className="text-cyber-green flex-shrink-0" />
        }
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-5 border-t border-cyber-border/20 bg-cyber-bg/30">

              {/* Detail KPIs */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4 mb-4">
                {[
                  { label: 'Attempts/sec', value: r.attempts_per_sec?.toLocaleString() || '—', color: 'text-cyber-cyan' },
                  { label: 'Avg Crack ms', value: r.avg_crack_time_ms?.toFixed(4) || '—',      color: 'text-yellow-400' },
                  { label: 'Wordlist Size',value: r.wordlist_size?.toLocaleString() || '—',    color: 'text-cyber-purple' },
                  { label: 'Stopped Early',value: r.stopped_early ? 'Yes' : 'No',              color: r.stopped_early ? 'text-yellow-400' : 'text-cyber-green' },
                ].map(({ label, value, color }) => (
                  <div key={label} className="bg-cyber-card/50 rounded-xl p-3 border border-cyber-border/20">
                    <p className="text-[10px] text-cyber-muted font-mono mb-1">{label}</p>
                    <p className={`text-sm font-mono font-bold ${color}`}>{value}</p>
                  </div>
                ))}
              </div>

              {/* Notes */}
              {r.notes && (
                <p className="text-[11px] font-mono text-cyber-muted/70 mb-3 bg-cyber-card/30 rounded-lg px-3 py-2 border border-cyber-border/20">
                  {r.notes}
                </p>
              )}

              {/* Cracked sample */}
              {log.cracked_sample?.length > 0 && (
                <div className="mb-3">
                  <p className="text-[10px] font-mono text-cyber-red mb-2">CRACKED PASSWORDS (sample):</p>
                  <div className="flex flex-wrap gap-2">
                    {log.cracked_sample.slice(0, 10).map((c, i) => (
                      <span key={i}
                        className="text-[11px] font-mono bg-cyber-red/8 border border-cyber-red/20 text-cyber-red px-2.5 py-1 rounded-lg">
                        "{c.plain_password}"
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Raw JSON */}
              <div>
                <p className="text-[10px] font-mono text-cyber-muted mb-1.5">RAW JSON:</p>
                <pre className="text-[9px] text-cyber-text/40 bg-black/40 rounded-xl p-3 overflow-x-auto max-h-28 font-mono border border-cyber-border/20">
                  {JSON.stringify(log, null, 2).slice(0, 800)}
                </pre>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

export default function LogsReports() {
  const [logs,    setLogs]    = useState([])
  const [results, setResults] = useState([])
  const [search,  setSearch]  = useState('')
  const [loading, setLoading] = useState(true)
  const [tab,     setTab]     = useState('logs')
  const [atkFilter, setAtkFilter] = useState('all')

  const ATTACK_TYPES = ['all', 'dictionary', 'brute_force', 'rainbow_table', 'hybrid']

  const load = () => {
    setLoading(true)
    Promise.all([
      getAttackLogs(100).then(r => setLogs(r.data.logs || [])).catch(() => {}),
      getAttackResults({ limit: 200 }).then(r => setResults(r.data.results || [])).catch(() => {}),
    ]).finally(() => setLoading(false))
  }
  useEffect(load, [])

  const filteredLogs = logs.filter(l =>
    (atkFilter === 'all' || l.attack_type === atkFilter) &&
    (l.attack_type?.includes(search.toLowerCase()) ||
     l.algorithm?.toLowerCase().includes(search.toLowerCase()) ||
     l.timestamp?.includes(search))
  )

  const filteredRes = results.filter(r =>
    (atkFilter === 'all' || r.attack_type === atkFilter) &&
    (r.attack_type?.includes(search.toLowerCase()) ||
     r.algorithm?.toLowerCase().includes(search.toLowerCase()))
  )

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' })
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
    a.download = 'cipherguard_logs.json'; a.click()
  }

  const exportCSV = () => {
    if (!results.length) return
    const h = Object.keys(results[0]).join(',')
    const rows = results.map(r => Object.values(r).map(v => JSON.stringify(v)).join(','))
    const blob = new Blob([[h, ...rows].join('\n')], { type: 'text/csv' })
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
    a.download = 'attack_results.csv'; a.click()
  }

  // Summary stats
  const stats = {
    totalRuns:    results.length,
    cracked:      results.reduce((s, r) => s + (r.cracked_count || 0), 0),
    avgRate:      results.length ? (results.reduce((s, r) => s + r.success_rate_pct, 0) / results.length).toFixed(1) : 0,
    mostAttacked: results.reduce((acc, r) => { acc[r.algorithm] = (acc[r.algorithm] || 0) + 1; return acc }, {}),
  }

  return (
    <div className="page-container">

      {/* ── Summary Strip ─────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Total Logs',     value: logs.length,  color: 'text-cyber-cyan',   icon: FileText  },
          { label: 'Attack Runs',    value: stats.totalRuns, color: 'text-cyber-purple', icon: Zap     },
          { label: 'Total Cracked',  value: stats.cracked, color: stats.cracked > 0 ? 'text-cyber-red' : 'text-cyber-green', icon: AlertCircle },
          { label: 'Avg Crack Rate', value: `${stats.avgRate}%`, color: 'text-yellow-400', icon: Activity },
        ].map(({ label, value, color, icon: I }) => (
          <motion.div key={label}
            initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
            className="glass-card px-4 py-3.5 border border-cyber-border/30 flex items-center gap-3">
            <div className={`w-9 h-9 rounded-xl bg-current/10 flex items-center justify-center ${color}`}
                 style={{ background: 'rgba(0,0,0,0.2)' }}>
              <I size={16} className={color} />
            </div>
            <div>
              <p className={`text-xl font-extrabold font-mono ${color}`}>{loading ? '—' : value}</p>
              <p className="text-[10px] text-cyber-muted font-medium">{label}</p>
            </div>
          </motion.div>
        ))}
      </div>

      {/* ── Toolbar ───────────────────────────────────────────── */}
      <div className="flex items-center gap-3 flex-wrap">
        {/* Tabs */}
        <div className="flex items-center gap-1 p-1 bg-cyber-card/60 border border-cyber-border/40 rounded-xl">
          {[['logs', `Logs (${logs.length})`, FileText], ['results', `Results (${results.length})`, Database]].map(([v, l, I]) => (
            <button key={v} onClick={() => setTab(v)}
              className={`flex items-center gap-1.5 ${tab === v ? 'tab-btn-active' : 'tab-btn-inactive'}`}>
              <I size={12} />{l}
            </button>
          ))}
        </div>

        {/* Attack type filter */}
        <div className="flex items-center gap-1 p-1 bg-cyber-card/60 border border-cyber-border/40 rounded-xl">
          {ATTACK_TYPES.map(t => (
            <button key={t} onClick={() => setAtkFilter(t)}
              className={atkFilter === t ? 'tab-btn-active' : 'tab-btn-inactive'}>
              {t === 'all' ? 'All' : t.split('_').map(w => w[0].toUpperCase() + w.slice(1)).join(' ')}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="flex items-center gap-2 bg-cyber-card/60 border border-cyber-border/40 rounded-xl px-3 py-2 min-w-[180px]">
          <Search size={13} className="text-cyber-muted flex-shrink-0" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Filter by algo, attack..."
            className="bg-transparent text-xs text-cyber-text outline-none w-full font-mono placeholder:text-cyber-muted/30" />
        </div>

        <div className="flex items-center gap-2 ml-auto">
          <button onClick={load} className="btn-cyan">
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
          {tab === 'logs'
            ? <button onClick={exportJSON} className="btn-purple"><Download size={13} /> JSON</button>
            : <button onClick={exportCSV}  className="btn-green"><Download size={13} /> CSV</button>
          }
        </div>
      </div>

      {/* ── Logs View ─────────────────────────────────────────── */}
      {tab === 'logs' && (
        <div>
          {loading ? (
            <div className="flex items-center justify-center h-40 gap-3 text-cyber-muted">
              <RefreshCw size={20} className="animate-spin text-cyber-cyan" />
              <span className="font-mono text-sm">Loading logs...</span>
            </div>
          ) : filteredLogs.length === 0 ? (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
              className="glass-card p-14 text-center border border-cyber-border/20">
              <FileText size={40} className="mx-auto mb-4 text-cyber-muted/20" />
              <p className="text-sm font-bold text-cyber-text mb-2">
                {search || atkFilter !== 'all' ? 'No matching logs' : 'No logs yet'}
              </p>
              <p className="text-xs text-cyber-muted font-mono">
                {search || atkFilter !== 'all' ? 'Try adjusting your filters' : 'Run experiments to generate attack logs'}
              </p>
            </motion.div>
          ) : (
            <div>
              {filteredLogs.map((log, i) => <LogRow key={log.run_id || i} log={log} index={i} />)}
              <p className="text-xs text-cyber-muted font-mono text-center mt-3">{filteredLogs.length} log entries displayed</p>
            </div>
          )}
        </div>
      )}

      {/* ── Results Table View ────────────────────────────────── */}
      {tab === 'results' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="glass-card overflow-hidden">
          {filteredRes.length === 0 ? (
            <div className="p-14 text-center">
              <Database size={40} className="mx-auto mb-4 text-cyber-muted/20" />
              <p className="text-sm font-bold text-cyber-text mb-2">
                {search ? 'No matching results' : 'No results yet'}
              </p>
              <p className="text-xs text-cyber-muted font-mono">
                {search ? 'Try adjusting your search' : 'Run experiments to populate results'}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="cyber-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Attack</th>
                    <th>Algorithm</th>
                    <th>Cracked / Total</th>
                    <th>Success Rate</th>
                    <th>Speed</th>
                    <th>Score</th>
                    <th>Duration</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRes.map((r, i) => (
                    <motion.tr key={r.id || i}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: i * 0.03 }}
                    >
                      <td><span className="text-cyber-muted font-mono text-xs">#{r.id}</span></td>
                      <td>
                        <Badge variant={ATTACK_COLORS[r.attack_type]?.badge || 'gray'}>
                          {r.attack_type?.replace(/_/g, ' ')}
                        </Badge>
                      </td>
                      <td><span className="font-mono text-xs font-bold text-cyber-text">{r.algorithm}</span></td>
                      <td>
                        <span className={`font-mono text-xs font-bold ${r.cracked_count > 0 ? 'text-cyber-red' : 'text-cyber-green'}`}>
                          {r.cracked_count}
                        </span>
                        <span className="text-cyber-muted font-mono text-xs">/{r.target_count}</span>
                      </td>
                      <td>
                        <div className="flex items-center gap-2">
                          <div className="progress-bar w-12">
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
                      <td><span className="font-mono text-xs text-cyber-cyan">{r.attempts_per_sec?.toLocaleString()}/s</span></td>
                      <td>
                        <span className="font-mono text-xs font-bold" style={{
                          color: (r.security_score || 0) >= 70 ? '#00ff88' : (r.security_score || 0) >= 40 ? '#ffd700' : '#ff3366'
                        }}>
                          {r.security_score?.toFixed(0) || '—'}
                        </span>
                      </td>
                      <td><span className="font-mono text-xs text-cyber-muted">{r.total_time_sec?.toFixed(3)}s</span></td>
                      <td><span className="font-mono text-xs text-cyber-muted">{r.created_at?.slice(0, 16)?.replace('T', ' ')}</span></td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
              <div className="px-5 py-3 border-t border-cyber-border/20 text-xs font-mono text-cyber-muted text-center">
                {filteredRes.length} results
              </div>
            </div>
          )}
        </motion.div>
      )}
    </div>
  )
}
