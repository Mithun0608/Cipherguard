import { useState } from 'react'
import { motion } from 'framer-motion'
import {
  Settings as SettingsIcon, Shield, Database, Zap, Bell, Palette,
  Server, Lock, RefreshCw, Save, CheckCircle, AlertTriangle,
  Monitor, Moon, Globe, Key, Cpu, ToggleLeft, ToggleRight
} from 'lucide-react'
import { Badge } from '../components/ui/Badges'
import { healthCheck } from '../services/api'

function Toggle({ value, onChange, label, sub, disabled }) {
  return (
    <div className={`flex items-start justify-between gap-4 py-4 border-b border-cyber-border/20 ${disabled ? 'opacity-40' : ''}`}>
      <div>
        <p className="text-sm font-medium text-cyber-text">{label}</p>
        {sub && <p className="text-xs text-cyber-muted font-mono mt-0.5">{sub}</p>}
      </div>
      <button
        onClick={() => !disabled && onChange(!value)}
        disabled={disabled}
        className={`flex-shrink-0 w-11 h-6 rounded-full transition-all duration-300 relative ${
          value ? 'bg-cyber-cyan' : 'bg-cyber-border'
        }`}
        style={{ boxShadow: value ? '0 0 12px rgba(0,245,255,0.4)' : 'none' }}
      >
        <motion.div
          animate={{ x: value ? 22 : 2 }}
          transition={{ type: 'spring', stiffness: 500, damping: 30 }}
          className="absolute top-1 w-4 h-4 rounded-full bg-cyber-bg shadow-md"
        />
      </button>
    </div>
  )
}

function SettingSection({ title, icon: Icon, color = 'cyan', children }) {
  const colorMap = {
    cyan:   'text-cyber-cyan bg-cyber-cyan/10 border-cyber-cyan/30',
    purple: 'text-cyber-purple bg-cyber-purple/10 border-cyber-purple/30',
    green:  'text-cyber-green bg-cyber-green/10 border-cyber-green/30',
    red:    'text-cyber-red bg-cyber-red/10 border-cyber-red/30',
    yellow: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
  }
  const [textC, bgC, borderC] = colorMap[color].split(' ')
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card p-5"
    >
      <div className="flex items-center gap-3 mb-5 pb-3 border-b border-cyber-border/30">
        <div className={`w-9 h-9 rounded-xl ${bgC} border ${borderC} flex items-center justify-center flex-shrink-0`}>
          <Icon size={16} className={textC} />
        </div>
        <h3 className="text-sm font-bold text-cyber-text">{title}</h3>
      </div>
      {children}
    </motion.div>
  )
}

export default function Settings() {
  const [apiUrl,       setApiUrl]       = useState('http://127.0.0.1:8000')
  const [apiStatus,    setApiStatus]    = useState(null)
  const [testing,      setTesting]      = useState(false)
  const [saved,        setSaved]        = useState(false)

  // Toggles
  const [darkMode,       setDarkMode]       = useState(true)
  const [liveUpdates,    setLiveUpdates]    = useState(true)
  const [notifications,  setNotifications]  = useState(true)
  const [autoRefresh,    setAutoRefresh]    = useState(false)
  const [compactView,    setCompactView]    = useState(false)
  const [animationsOn,   setAnimationsOn]   = useState(true)
  const [soundAlerts,    setSoundAlerts]    = useState(false)
  const [autoExport,     setAutoExport]     = useState(false)

  // Number settings
  const [refreshInterval, setRefreshInterval] = useState(8)
  const [maxLogEntries,   setMaxLogEntries]   = useState(100)
  const [defaultLimit,    setDefaultLimit]    = useState(30)

  const testConnection = async () => {
    setTesting(true); setApiStatus(null)
    try {
      await healthCheck()
      setApiStatus('online')
    } catch {
      setApiStatus('offline')
    }
    setTesting(false)
  }

  const saveSettings = () => {
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div className="page-container max-w-4xl">

      {/* ── Header ────────────────────────────────────────────── */}
      <motion.div initial={{ opacity: 0, y: -16 }} animate={{ opacity: 1, y: 0 }}
        className="card-cyan p-5 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyber-cyan/10 border border-cyber-cyan/30 flex items-center justify-center">
            <SettingsIcon size={18} className="text-cyber-cyan" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-cyber-text">System Configuration</h3>
            <p className="text-xs text-cyber-muted font-mono">CipherGuard v3.0 — Phase III settings</p>
          </div>
        </div>
        <motion.button
          onClick={saveSettings}
          whileTap={{ scale: 0.96 }}
          className={`flex items-center gap-2 px-5 py-2.5 rounded-xl font-mono text-sm font-bold transition-all duration-300 ${
            saved
              ? 'bg-cyber-green/20 border border-cyber-green/50 text-cyber-green shadow-glow-green'
              : 'btn-solid-cyan'
          }`}
        >
          {saved ? <><CheckCircle size={15} /> Saved!</> : <><Save size={15} /> Save Settings</>}
        </motion.button>
      </motion.div>

      {/* ── API Connection ────────────────────────────────────── */}
      <SettingSection title="API Connection" icon={Server} color="cyan">
        <div className="space-y-4">
          <div>
            <label className="text-[10px] font-mono text-cyber-muted uppercase tracking-wide mb-1.5 block">Backend URL</label>
            <div className="flex gap-3">
              <input value={apiUrl} onChange={e => setApiUrl(e.target.value)}
                className="cyber-input flex-1" />
              <button onClick={testConnection} disabled={testing}
                className="btn-cyan whitespace-nowrap">
                {testing ? <RefreshCw size={13} className="animate-spin" /> : <Globe size={13} />}
                {testing ? 'Testing...' : 'Test'}
              </button>
            </div>
            {apiStatus && (
              <motion.div initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }}
                className={`mt-2 flex items-center gap-2 text-xs font-mono px-3 py-2 rounded-lg border ${
                  apiStatus === 'online'
                    ? 'bg-cyber-green/8 border-cyber-green/30 text-cyber-green'
                    : 'bg-cyber-red/8 border-cyber-red/30 text-cyber-red'
                }`}>
                {apiStatus === 'online'
                  ? <><CheckCircle size={13} /> Backend is online and responding</>
                  : <><AlertTriangle size={13} /> Backend unreachable — check FastAPI server</>
                }
              </motion.div>
            )}
          </div>

          <div className="grid grid-cols-3 gap-4">
            {[
              { label: 'Health Interval (sec)', val: refreshInterval, set: setRefreshInterval, min: 3, max: 60 },
              { label: 'Max Log Entries',       val: maxLogEntries,   set: setMaxLogEntries,   min: 10, max: 500 },
              { label: 'Default Target Limit',  val: defaultLimit,    set: setDefaultLimit,    min: 5,  max: 200 },
            ].map(({ label, val, set, min, max }) => (
              <div key={label}>
                <label className="text-[10px] font-mono text-cyber-muted uppercase tracking-wide mb-1.5 block">{label}</label>
                <input type="number" value={val} min={min} max={max}
                  onChange={e => set(Number(e.target.value))}
                  className="cyber-input text-center font-bold" />
              </div>
            ))}
          </div>
        </div>
      </SettingSection>

      {/* ── Appearance ────────────────────────────────────────── */}
      <SettingSection title="Appearance & UI" icon={Palette} color="purple">
        <Toggle value={darkMode}     onChange={setDarkMode}     label="Dark Mode"          sub="CyberSec dark theme (recommended)" />
        <Toggle value={animationsOn} onChange={setAnimationsOn} label="Animations"         sub="Framer Motion page transitions and card effects" />
        <Toggle value={compactView}  onChange={setCompactView}  label="Compact View"       sub="Reduce padding and spacing in tables" />
      </SettingSection>

      {/* ── Live Data ─────────────────────────────────────────── */}
      <SettingSection title="Live Data & Updates" icon={Zap} color="green">
        <Toggle value={liveUpdates}  onChange={setLiveUpdates}  label="Live Feed Updates"  sub="Poll attack results every 8 seconds on dashboard" />
        <Toggle value={autoRefresh}  onChange={setAutoRefresh}  label="Auto Refresh"       sub="Automatically refresh data on page focus" />
        <Toggle value={autoExport}   onChange={setAutoExport}   label="Auto Export"        sub="Auto-export CSV after each experiment run" />
      </SettingSection>

      {/* ── Notifications ─────────────────────────────────────── */}
      <SettingSection title="Notifications & Alerts" icon={Bell} color="yellow">
        <Toggle value={notifications} onChange={setNotifications} label="System Notifications" sub="Show event badge on bell icon" />
        <Toggle value={soundAlerts}   onChange={setSoundAlerts}   label="Sound Alerts"         sub="Play audio on critical breach events" disabled />
      </SettingSection>

      {/* ── System Info ───────────────────────────────────────── */}
      <SettingSection title="System Information" icon={Monitor} color="red">
        <div className="grid grid-cols-2 gap-3">
          {[
            { label: 'Frontend',       value: 'React 19 + Vite 8',     color: 'text-cyber-cyan'   },
            { label: 'Styling',        value: 'Tailwind CSS 3',        color: 'text-cyber-cyan'   },
            { label: 'Charts',         value: 'Recharts 3',            color: 'text-cyber-purple' },
            { label: 'Animations',     value: 'Framer Motion 12',      color: 'text-cyber-purple' },
            { label: 'Backend',        value: 'FastAPI + SQLite',       color: 'text-cyber-green'  },
            { label: 'Hashing',        value: 'bcrypt, argon2, SHA',   color: 'text-cyber-green'  },
            { label: 'Algorithms',     value: '7 evaluated',           color: 'text-yellow-400'   },
            { label: 'Attack Vectors', value: '4 simulations',         color: 'text-yellow-400'   },
            { label: 'Version',        value: 'v3.0.0 — Phase III',    color: 'text-cyber-cyan'   },
            { label: 'Project',        value: 'CipherGuard',           color: 'text-cyber-text'   },
          ].map(({ label, value, color }) => (
            <div key={label} className="flex items-center justify-between bg-cyber-card/40 rounded-xl px-3 py-2.5 border border-cyber-border/20">
              <span className="text-xs text-cyber-muted font-mono">{label}</span>
              <span className={`text-xs font-mono font-bold ${color}`}>{value}</span>
            </div>
          ))}
        </div>

        {/* Algorithms listing */}
        <div className="mt-4 pt-4 border-t border-cyber-border/20">
          <p className="text-[10px] font-mono text-cyber-muted uppercase tracking-wide mb-3">Evaluated Algorithms</p>
          <div className="flex flex-wrap gap-2">
            {[
              { name: 'Plaintext',      tier: 'red',    note: 'CRITICAL' },
              { name: 'MD5',            tier: 'red',    note: 'CRITICAL' },
              { name: 'SHA-1',          tier: 'red',    note: 'DEPRECATED' },
              { name: 'SHA-256',        tier: 'yellow', note: 'WEAK' },
              { name: 'Salted SHA-256', tier: 'cyan',   note: 'MODERATE' },
              { name: 'bcrypt',         tier: 'green',  note: 'STRONG' },
              { name: 'Argon2id',       tier: 'green',  note: 'RECOMMENDED' },
            ].map(({ name, tier, note }) => (
              <div key={name} className={`badge badge-${tier}`}>
                <span>{name}</span>
                <span className="opacity-60">· {note}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Reset button */}
        <div className="mt-5 pt-4 border-t border-cyber-border/20 flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-cyber-text">Reset to Defaults</p>
            <p className="text-xs text-cyber-muted font-mono">Restore all settings to factory defaults</p>
          </div>
          <button className="btn-red text-xs">
            <AlertTriangle size={13} /> Reset
          </button>
        </div>
      </SettingSection>
    </div>
  )
}
