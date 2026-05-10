import { motion } from 'framer-motion'
import { TrendingUp, TrendingDown, Minus } from 'lucide-react'
import { SparklineChart } from './Charts'

const COLORS = {
  cyan:   {
    border: 'border-cyber-cyan/25', hoverBorder: 'hover:border-cyber-cyan/60',
    glow: 'hover:shadow-glow-cyan', text: 'text-cyber-cyan', textGlow: 'text-glow-cyan',
    bg: 'bg-gradient-card-cyan', iconBg: 'bg-cyber-cyan/10', iconBorder: 'border-cyber-cyan/30',
    sparkColor: '#00f5ff'
  },
  purple: {
    border: 'border-cyber-purple/25', hoverBorder: 'hover:border-cyber-purple/60',
    glow: 'hover:shadow-glow-purple', text: 'text-cyber-purple', textGlow: 'text-glow-purple',
    bg: 'bg-gradient-card-purple', iconBg: 'bg-cyber-purple/10', iconBorder: 'border-cyber-purple/30',
    sparkColor: '#8b5cf6'
  },
  green:  {
    border: 'border-cyber-green/25', hoverBorder: 'hover:border-cyber-green/60',
    glow: 'hover:shadow-glow-green', text: 'text-cyber-green', textGlow: 'text-glow-green',
    bg: 'bg-gradient-card-green', iconBg: 'bg-cyber-green/10', iconBorder: 'border-cyber-green/30',
    sparkColor: '#00ff88'
  },
  red:    {
    border: 'border-cyber-red/25', hoverBorder: 'hover:border-cyber-red/60',
    glow: 'hover:shadow-glow-red', text: 'text-cyber-red', textGlow: 'text-glow-red',
    bg: 'bg-gradient-card-red', iconBg: 'bg-cyber-red/10', iconBorder: 'border-cyber-red/30',
    sparkColor: '#ff3366'
  },
  yellow: {
    border: 'border-yellow-400/25', hoverBorder: 'hover:border-yellow-400/60',
    glow: 'hover:shadow-glow-yellow', text: 'text-yellow-400', textGlow: 'text-glow-yellow',
    bg: 'bg-gradient-card-cyan', iconBg: 'bg-yellow-400/10', iconBorder: 'border-yellow-400/30',
    sparkColor: '#ffd700'
  },
}

// Tiny sparkline data generator
function spark(base, count = 7) {
  return Array.from({ length: count }, (_, i) => ({
    v: Math.max(0, base + (Math.random() - 0.5) * base * 0.4)
  }))
}

export default function StatCard({
  label, value, icon: Icon, color = 'cyan',
  sub, trend, loading = false, delay = 0,
  sparkData, unit = '',
}) {
  const c = COLORS[color] || COLORS.cyan
  const data = sparkData || spark(50)

  return (
    <motion.div
      initial={{ opacity: 0, y: 24, scale: 0.96 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ delay, duration: 0.45, ease: [0.4, 0, 0.2, 1] }}
      whileHover={{ y: -4 }}
      className={`stat-card border ${c.border} ${c.hoverBorder} ${c.glow} ${c.bg}
                  transition-all duration-300 cursor-default relative overflow-hidden`}
    >
      {/* Corner glow */}
      <div className={`absolute top-0 right-0 w-20 h-20 rounded-full opacity-20 blur-2xl pointer-events-none`}
           style={{ background: c.sparkColor }} />

      <div className="flex items-start justify-between mb-3 relative z-10">
        <div className={`w-10 h-10 rounded-xl ${c.iconBg} border ${c.iconBorder} flex items-center justify-center flex-shrink-0`}
             style={{ boxShadow: `0 0 12px ${c.sparkColor}25` }}>
          {Icon && <Icon size={18} className={c.text} />}
        </div>

        {/* Trend */}
        {trend !== undefined && (
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ delay: delay + 0.3 }}
            className={`flex items-center gap-1 text-xs font-mono px-2 py-0.5 rounded-full ${
              trend > 0
                ? 'bg-cyber-green/10 text-cyber-green border border-cyber-green/20'
                : trend < 0
                  ? 'bg-cyber-red/10 text-cyber-red border border-cyber-red/20'
                  : 'bg-cyber-muted/10 text-cyber-muted border border-cyber-muted/20'
            }`}
          >
            {trend > 0 ? <TrendingUp size={10} /> : trend < 0 ? <TrendingDown size={10} /> : <Minus size={10} />}
            <span>{Math.abs(trend)}%</span>
          </motion.div>
        )}
      </div>

      {/* Value */}
      {loading ? (
        <div className="space-y-2.5 mb-3">
          <div className="skeleton h-8 w-3/4" />
          <div className="skeleton h-3 w-1/2" />
        </div>
      ) : (
        <div className="mb-3 relative z-10">
          <motion.p
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: delay + 0.15, type: 'spring', stiffness: 200 }}
            className={`text-2xl font-extrabold font-mono ${c.text} ${c.textGlow} leading-none mb-1`}
          >
            {value ?? '—'}{unit}
          </motion.p>
          <p className="text-xs font-medium text-cyber-muted">{label}</p>
          {sub && <p className="text-[10px] text-cyber-muted/50 font-mono mt-0.5">{sub}</p>}
        </div>
      )}

      {/* Sparkline */}
      <div className="h-10 relative z-10 opacity-60">
        <SparklineChart data={data} color={c.sparkColor} />
      </div>
    </motion.div>
  )
}
