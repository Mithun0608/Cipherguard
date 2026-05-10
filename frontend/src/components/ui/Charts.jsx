import { ResponsiveContainer, AreaChart, Area, Tooltip } from 'recharts'
import { motion } from 'framer-motion'

// ── Sparkline (tiny area chart) ────────────────────────────────────────────
export function SparklineChart({ data, color = '#00f5ff', height = 40 }) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
        <defs>
          <linearGradient id={`spark-${color.replace('#', '')}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor={color} stopOpacity={0.3} />
            <stop offset="95%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
        <Area
          type="monotone"
          dataKey="v"
          stroke={color}
          strokeWidth={1.5}
          fill={`url(#spark-${color.replace('#', '')})`}
          dot={false}
          isAnimationActive={true}
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}

// ── Custom chart tooltip ───────────────────────────────────────────────────
export function CyberTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="glass-card px-3 py-2.5 text-xs font-mono border border-cyber-border/60"
         style={{ boxShadow: '0 8px 32px rgba(0,0,0,0.4)' }}>
      {label && <p className="text-cyber-cyan mb-1.5 font-semibold">{label}</p>}
      {payload.map((p, i) => (
        <div key={i} className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: p.color }} />
          <span className="text-cyber-muted">{p.name}:</span>
          <span style={{ color: p.color }} className="font-semibold">
            {typeof p.value === 'number' ? p.value.toFixed(2) : p.value}
          </span>
        </div>
      ))}
    </div>
  )
}

// ── Animated progress bar ──────────────────────────────────────────────────
export function ProgressBar({ value, max = 100, color = '#00f5ff', height = 6, delay = 0, label }) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100))
  return (
    <div>
      {label && (
        <div className="flex justify-between text-xs font-mono mb-1">
          <span className="text-cyber-muted">{label}</span>
          <span style={{ color }}>{value}</span>
        </div>
      )}
      <div className="progress-bar" style={{ height }}>
        <motion.div
          className="h-full rounded-full"
          style={{ background: color, boxShadow: `0 0 8px ${color}60` }}
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ delay, duration: 0.9, ease: [0.4, 0, 0.2, 1] }}
        />
      </div>
    </div>
  )
}

// ── Score ring (SVG circular progress) ────────────────────────────────────
export function ScoreRing({ score = 0, size = 80, strokeWidth = 6, grade = '', color }) {
  const r = (size - strokeWidth) / 2
  const circ = 2 * Math.PI * r
  const offset = circ - (score / 100) * circ
  const clr = color || (score >= 70 ? '#00ff88' : score >= 40 ? '#ffd700' : '#ff3366')

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg className="-rotate-90" width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={size / 2} cy={size / 2} r={r}
          stroke="rgba(30,58,95,0.6)" strokeWidth={strokeWidth} fill="none"
        />
        <motion.circle
          cx={size / 2} cy={size / 2} r={r}
          stroke={clr} strokeWidth={strokeWidth} fill="none"
          strokeLinecap="round"
          strokeDasharray={circ}
          initial={{ strokeDashoffset: circ }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1.4, ease: [0.4, 0, 0.2, 1] }}
          style={{ filter: `drop-shadow(0 0 6px ${clr})` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        {grade && <span className="font-extrabold font-mono leading-none" style={{ color: clr, fontSize: size * 0.22 }}>{grade}</span>}
        <span className="font-mono text-cyber-muted leading-none" style={{ fontSize: size * 0.13 }}>{score}</span>
      </div>
    </div>
  )
}

// ── Heatmap cell ────────────────────────────────────────────────────────────
export function HeatCell({ value, max = 100, label, sublabel }) {
  const intensity = value / max
  const color = intensity > 0.7 ? '#ff3366' : intensity > 0.4 ? '#ffd700' : '#00ff88'
  return (
    <div className="glass-card p-3 text-center border transition-all duration-200 hover:-translate-y-0.5"
         style={{ borderColor: `${color}30`, background: `linear-gradient(135deg, ${color}08 0%, transparent 60%)` }}>
      <div className="text-lg font-extrabold font-mono mb-0.5" style={{ color, textShadow: `0 0 10px ${color}60` }}>
        {value}
      </div>
      <div className="text-[10px] font-mono text-cyber-muted">{label}</div>
      {sublabel && <div className="text-[9px] font-mono text-cyber-muted/50">{sublabel}</div>}
    </div>
  )
}
