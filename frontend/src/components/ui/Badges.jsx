import { motion } from 'framer-motion'

// ── Generic badge ──────────────────────────────────────────────────────────
export function Badge({ children, variant = 'cyan' }) {
  return <span className={`badge badge-${variant}`}>{children}</span>
}

// ── Security level badge ───────────────────────────────────────────────────
export function SecurityBadge({ score }) {
  if (score >= 75) return <Badge variant="green">SECURE</Badge>
  if (score >= 50) return <Badge variant="yellow">MODERATE</Badge>
  if (score >= 25) return <Badge variant="red">WEAK</Badge>
  return <Badge variant="red">CRITICAL</Badge>
}

// ── Risk level badge ───────────────────────────────────────────────────────
export function RiskBadge({ level }) {
  const map = { CRITICAL: 'red', HIGH: 'red', MEDIUM: 'yellow', LOW: 'green' }
  return (
    <span className={`badge badge-${map[level] || 'gray'} font-bold`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />
      {level}
    </span>
  )
}

// ── Algorithm tier badge ───────────────────────────────────────────────────
export function AlgoBadge({ algo }) {
  const weak = ['plaintext', 'md5', 'sha1', 'sha256']
  const v = weak.includes(algo) ? 'red' : 'green'
  return <Badge variant={v}>{algo.toUpperCase()}</Badge>
}

// ── Attack type badge ──────────────────────────────────────────────────────
export function AttackBadge({ type }) {
  const map = { dictionary: 'cyan', brute_force: 'purple', rainbow_table: 'yellow', hybrid: 'orange' }
  return <Badge variant={map[type] || 'gray'}>{type?.replace(/_/g, ' ')}</Badge>
}

// ── Status dot ────────────────────────────────────────────────────────────
export function StatusDot({ active, label }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className={`w-2 h-2 rounded-full flex-shrink-0 ${active ? 'bg-cyber-green animate-pulse' : 'bg-cyber-muted'}`} />
      {label && <span className={`text-xs font-mono ${active ? 'text-cyber-green' : 'text-cyber-muted'}`}>{label}</span>}
    </div>
  )
}

// ── Grade circle (SVG donut) ───────────────────────────────────────────────
export function GradeCircle({ grade, score, size = 64 }) {
  const COLOR = { A: '#00ff88', B: '#00f5ff', C: '#ffd700', D: '#ff8c00', F: '#ff3366' }
  const color = COLOR[grade] || '#64748b'
  const r = 28, circ = 2 * Math.PI * r, fill = circ - (score / 100) * circ

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg className="-rotate-90" width={size} height={size} viewBox="0 0 72 72">
        <circle cx="36" cy="36" r={r} stroke="rgba(30,58,95,0.5)" strokeWidth="5" fill="none" />
        <motion.circle
          cx="36" cy="36" r={r}
          stroke={color} strokeWidth="5" fill="none"
          strokeLinecap="round"
          strokeDasharray={circ}
          initial={{ strokeDashoffset: circ }}
          animate={{ strokeDashoffset: fill }}
          transition={{ duration: 1.2, ease: 'easeOut' }}
          style={{ filter: `drop-shadow(0 0 6px ${color})` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-lg font-extrabold font-mono leading-none" style={{ color }}>{grade}</span>
        <span className="text-[9px] text-cyber-muted font-mono">{score}</span>
      </div>
    </div>
  )
}

// ── Crack status cell ──────────────────────────────────────────────────────
export function CrackStatus({ cracked }) {
  return cracked
    ? <Badge variant="red"><span className="animate-pulse">●</span> CRACKED</Badge>
    : <Badge variant="green">SECURE</Badge>
}

// ── Info card ──────────────────────────────────────────────────────────────
export function InfoCard({ label, value, color = 'cyan', size = 'md' }) {
  const sizeMap = { sm: 'text-lg', md: 'text-2xl', lg: 'text-3xl' }
  const colorMap = {
    cyan:   'text-cyber-cyan text-glow-cyan',
    purple: 'text-cyber-purple text-glow-purple',
    green:  'text-cyber-green text-glow-green',
    red:    'text-cyber-red text-glow-red',
    yellow: 'text-yellow-400 text-glow-yellow',
  }
  return (
    <div className="bg-cyber-card/50 rounded-xl p-4 border border-cyber-border/30 text-center">
      <p className={`font-extrabold font-mono ${sizeMap[size]} ${colorMap[color] || colorMap.cyan} mb-1`}>{value}</p>
      <p className="text-xs text-cyber-muted font-medium">{label}</p>
    </div>
  )
}

// ── Section header ─────────────────────────────────────────────────────────
export function SectionHeader({ title, sub, icon: Icon, color = 'cyan', children }) {
  const colorMap = {
    cyan:   'text-cyber-cyan',
    purple: 'text-cyber-purple',
    green:  'text-cyber-green',
    red:    'text-cyber-red',
  }
  return (
    <div className="flex items-center justify-between mb-5">
      <div className="flex items-center gap-3">
        {Icon && (
          <div className={`w-8 h-8 rounded-lg bg-current/10 flex items-center justify-center ${colorMap[color]}`}
               style={{ background: `rgba(0,0,0,0.2)` }}>
            <Icon size={16} className={colorMap[color]} />
          </div>
        )}
        <div>
          <h3 className="text-sm font-bold text-cyber-text">{title}</h3>
          {sub && <p className="text-xs text-cyber-muted font-mono">{sub}</p>}
        </div>
      </div>
      {children && <div className="flex items-center gap-2">{children}</div>}
    </div>
  )
}
