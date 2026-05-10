import { useState, useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Shield, Wifi, WifiOff, Bell, Search, Activity,
  Zap, Lock, AlertCircle, ChevronDown, X
} from 'lucide-react'
import { healthCheck } from '../../services/api'

const PAGE_META = {
  '/dashboard':  { title: 'Mission Control',    sub: 'Security overview & real-time analytics',        crumb: ['Dashboard', 'Overview'] },
  '/experiment': { title: 'Experiment Runner',  sub: 'Configure and launch attack simulations',        crumb: ['Dashboard', 'Experiment'] },
  '/attacks':    { title: 'Attack Analysis',    sub: 'Detailed simulation results by attack vector',   crumb: ['Dashboard', 'Attacks'] },
  '/algorithms': { title: 'Algorithm Compare',  sub: 'Head-to-head algorithm benchmarks',             crumb: ['Dashboard', 'Algorithms'] },
  '/scorecard':  { title: 'Security Scorecard', sub: 'Algorithm security rankings and certifications', crumb: ['Dashboard', 'Scorecard'] },
  '/salting':    { title: 'Salting Visualizer', sub: 'Interactive salt protection demonstration',      crumb: ['Dashboard', 'Salting'] },
  '/breach':     { title: 'Breach Simulator',   sub: 'Advanced database breach attack simulation',     crumb: ['Dashboard', 'Breach'] },
  '/logs':       { title: 'Logs & Reports',     sub: 'Structured attack logs and exportable reports',  crumb: ['Dashboard', 'Logs'] },
  '/settings':   { title: 'Settings',           sub: 'Configuration and system preferences',           crumb: ['Dashboard', 'Settings'] },
}

const MOCK_NOTIFICATIONS = [
  { id: 1, type: 'error',   msg: 'MD5 cracked in 0.02ms — dictionary attack', time: '2m ago' },
  { id: 2, type: 'warn',    msg: 'bcrypt resisted brute force (30s timeout)',  time: '5m ago' },
  { id: 3, type: 'info',    msg: 'Security score computed for 7 algorithms',   time: '12m ago' },
  { id: 4, type: 'success', msg: 'Dataset generated: 350 hashes created',      time: '18m ago' },
]

const N_TYPE = { error: 'text-cyber-red', warn: 'text-yellow-400', info: 'text-cyber-cyan', success: 'text-cyber-green' }
const N_ICON = { error: '⚠', warn: '⚡', info: 'ℹ', success: '✓' }

export default function Navbar() {
  const location = useLocation()
  const [online, setOnline]       = useState(null)
  const [search, setSearch]       = useState('')
  const [showNotifs, setShowNotifs] = useState(false)
  const [unread, setUnread]       = useState(MOCK_NOTIFICATIONS.length)
  const page = PAGE_META[location.pathname] || { title: 'CipherGuard', sub: '', crumb: ['Dashboard'] }

  useEffect(() => {
    const check = async () => {
      try { await healthCheck(); setOnline(true) }
      catch { setOnline(false) }
    }
    check()
    const id = setInterval(check, 10_000)
    return () => clearInterval(id)
  }, [])

  return (
    <header className="h-16 flex items-center justify-between px-4 md:px-6 border-b border-cyber-border/60
                       bg-cyber-surface/80 backdrop-blur-xl flex-shrink-0 z-40 relative">

      {/* Animated top border glow */}
      <div className="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-cyber-cyan/30 to-transparent" />

      {/* Left: page title + breadcrumb */}
      <motion.div
        key={location.pathname}
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25 }}
        className="flex flex-col ml-10 md:ml-0"
      >
        <div className="flex items-center gap-2 text-[10px] font-mono text-cyber-muted/50 mb-0.5">
          {page.crumb.map((c, i) => (
            <span key={c} className="flex items-center gap-1">
              {i > 0 && <span className="opacity-40">/</span>}
              <span className={i === page.crumb.length - 1 ? 'text-cyber-cyan/70' : ''}>{c}</span>
            </span>
          ))}
        </div>
        <h1 className="text-base font-bold text-cyber-text leading-tight">{page.title}</h1>
      </motion.div>

      {/* Center: search */}
      <div className="hidden md:flex items-center gap-2.5 bg-cyber-card/60 border border-cyber-border/40
                      rounded-xl px-3.5 py-2 w-72 hover:border-cyber-cyan/30 transition-all duration-200
                      focus-within:border-cyber-cyan/40 focus-within:shadow-glow-sm group">
        <Search size={13} className="text-cyber-muted group-focus-within:text-cyber-cyan transition-colors" />
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search algorithms, attacks, logs..."
          className="bg-transparent text-sm text-cyber-text placeholder:text-cyber-muted/30 outline-none w-full font-mono"
        />
        {search && (
          <button onClick={() => setSearch('')} className="text-cyber-muted hover:text-cyber-red transition-colors">
            <X size={12} />
          </button>
        )}
      </div>

      {/* Right: status pills */}
      <div className="flex items-center gap-2">

        {/* Algo count */}
        <div className="hidden lg:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-card/60 border border-cyber-border/40">
          <Lock size={11} className="text-cyber-purple" />
          <span className="text-xs font-mono text-cyber-muted">
            <span className="text-cyber-purple font-semibold">7</span> algos
          </span>
        </div>

        {/* Attack count */}
        <div className="hidden lg:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-card/60 border border-cyber-border/40">
          <Zap size={11} className="text-cyber-red" />
          <span className="text-xs font-mono text-cyber-muted">
            <span className="text-cyber-red font-semibold">4</span> attacks
          </span>
        </div>

        {/* Backend status */}
        <motion.div
          animate={{ opacity: 1 }}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono transition-all duration-500 ${
            online === null
              ? 'bg-cyber-card/60 border-cyber-border/40 text-cyber-muted'
              : online
                ? 'bg-cyber-green/8 border-cyber-green/30 text-cyber-green'
                : 'bg-cyber-red/8 border-cyber-red/30 text-cyber-red'
          }`}
        >
          {online === null  ? <Activity size={11} className="animate-pulse" />
           : online         ? <Wifi size={11} />
           :                  <WifiOff size={11} />}
          <span>{online === null ? 'CHECKING' : online ? 'API LIVE' : 'OFFLINE'}</span>
          {online && <span className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse" />}
        </motion.div>

        {/* Notifications */}
        <div className="relative">
          <button
            onClick={() => { setShowNotifs(p => !p); setUnread(0) }}
            className="relative p-2 rounded-xl bg-cyber-card/60 border border-cyber-border/40
                       hover:border-cyber-cyan/30 hover:text-cyber-cyan text-cyber-muted transition-all duration-200"
          >
            <Bell size={15} />
            {unread > 0 && (
              <span className="absolute -top-0.5 -right-0.5 w-4 h-4 rounded-full bg-cyber-red text-white
                               text-[9px] font-bold flex items-center justify-center font-mono animate-pulse">
                {unread}
              </span>
            )}
          </button>

          <AnimatePresence>
            {showNotifs && (
              <motion.div
                initial={{ opacity: 0, y: 8, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 8, scale: 0.95 }}
                transition={{ duration: 0.15 }}
                className="absolute right-0 top-full mt-2 w-80 glass-card border border-cyber-border/60
                           shadow-2xl z-50"
                style={{ boxShadow: '0 20px 60px rgba(0,0,0,0.5), 0 0 30px rgba(0,245,255,0.05)' }}
              >
                <div className="flex items-center justify-between px-4 py-3 border-b border-cyber-border/30">
                  <div className="flex items-center gap-2">
                    <Bell size={13} className="text-cyber-cyan" />
                    <span className="text-xs font-mono font-semibold text-cyber-text">System Events</span>
                  </div>
                  <span className="text-[10px] font-mono text-cyber-muted">{MOCK_NOTIFICATIONS.length} events</span>
                </div>
                <div className="max-h-64 overflow-y-auto">
                  {MOCK_NOTIFICATIONS.map((n, i) => (
                    <motion.div
                      key={n.id}
                      initial={{ opacity: 0, x: 10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.05 }}
                      className="flex items-start gap-3 px-4 py-3 border-b border-cyber-border/20
                                 hover:bg-cyber-cyan/3 transition-colors"
                    >
                      <span className={`text-xs flex-shrink-0 mt-0.5 ${N_TYPE[n.type]}`}>{N_ICON[n.type]}</span>
                      <div className="flex-1 min-w-0">
                        <p className={`text-[11px] font-mono leading-snug ${N_TYPE[n.type]}`}>{n.msg}</p>
                        <p className="text-[10px] text-cyber-muted mt-0.5">{n.time}</p>
                      </div>
                    </motion.div>
                  ))}
                </div>
                <div className="px-4 py-2 text-center">
                  <button className="text-[11px] font-mono text-cyber-cyan hover:text-cyber-cyan/70 transition-colors">
                    View all in Logs →
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </header>
  )
}
