import { useRef, useCallback, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Terminal as TermIcon, Maximize2, Minimize2, Copy, Check, Trash2 } from 'lucide-react'

const LINE_STYLES = {
  cyan:    'text-cyber-cyan',
  green:   'text-cyber-green',
  success: 'text-cyber-green',
  error:   'text-cyber-red',
  warn:    'text-yellow-400',
  purple:  'text-cyber-purple',
  dim:     'text-cyber-muted/60',
  default: 'text-cyber-text/80',
  sep:     'text-cyber-border',
}

export function useTerminal() {
  const [lines, setLines] = useState([])

  const add = useCallback((text, type = 'default') => {
    const ts = new Date().toLocaleTimeString('en-US', { hour12: false })
    setLines(p => [...p, { text, type, ts }])
  }, [])

  const clear = useCallback(() => setLines([]), [])

  const sep = useCallback(() => {
    setLines(p => [...p, { text: '─'.repeat(52), type: 'sep' }])
  }, [])

  return { lines, add, clear, sep }
}

export default function Terminal({ lines = [], running = false, title = 'ATTACK ENGINE v3.0' }) {
  const bottomRef = useRef(null)
  const [expanded, setExpanded] = useState(false)
  const [copied, setCopied] = useState(false)

  const copyAll = () => {
    const text = lines.map(l => `[${l.ts}] ${l.text}`).join('\n')
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  // Auto-scroll
  const handleRef = (el) => {
    if (el) el.scrollTop = el.scrollHeight
  }

  return (
    <motion.div
      layout
      className={`terminal flex flex-col ${expanded ? 'fixed inset-6 z-50' : 'h-full min-h-80'}`}
    >
      {/* Terminal bar */}
      <div className="terminal-bar flex-shrink-0 flex items-center justify-between">
        <div className="flex items-center gap-3">
          {/* Traffic lights */}
          <div className="flex items-center gap-1.5">
            <span className="terminal-dot bg-cyber-red/80" />
            <span className="terminal-dot bg-yellow-400/80" />
            <span className="terminal-dot bg-cyber-green/80" />
          </div>
          <div className="flex items-center gap-2">
            <TermIcon size={12} className="text-cyber-cyan" />
            <span className="text-xs font-mono font-semibold text-cyber-cyan/80">{title}</span>
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          {running && (
            <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-cyber-red/10 border border-cyber-red/20">
              <span className="w-1.5 h-1.5 rounded-full bg-cyber-red animate-pulse" />
              <span className="text-[10px] font-mono text-cyber-red">RUNNING</span>
            </div>
          )}
          <button onClick={copyAll} className="p-1.5 rounded text-cyber-muted hover:text-cyber-cyan transition-colors">
            {copied ? <Check size={13} className="text-cyber-green" /> : <Copy size={13} />}
          </button>
          <button onClick={() => setExpanded(p => !p)} className="p-1.5 rounded text-cyber-muted hover:text-cyber-cyan transition-colors">
            {expanded ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
          </button>
        </div>
      </div>

      {/* Output */}
      <div
        ref={handleRef}
        className="flex-1 p-4 overflow-y-auto font-mono text-xs space-y-1 min-h-0"
        style={{ background: 'linear-gradient(180deg, #000a14 0%, #000510 100%)' }}
      >
        {lines.length === 0 ? (
          <div className="flex items-center gap-2 text-cyber-muted/30 mt-4">
            <TermIcon size={16} />
            <span>Awaiting command...</span>
          </div>
        ) : (
          <AnimatePresence initial={false}>
            {lines.map((l, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.15 }}
                className={`flex items-start gap-3 leading-relaxed ${LINE_STYLES[l.type] || LINE_STYLES.default}`}
              >
                <span className="text-cyber-muted/40 flex-shrink-0 text-[10px] pt-0.5 select-none">{l.ts}</span>
                <span className="flex-1">
                  {l.type === 'sep'
                    ? <span className="text-cyber-border/50">{l.text}</span>
                    : <><span className="text-cyber-muted/50 mr-2 select-none">❯</span>{l.text}</>
                  }
                </span>
              </motion.div>
            ))}
          </AnimatePresence>
        )}

        {running && (
          <motion.div
            animate={{ opacity: [1, 0] }}
            transition={{ repeat: Infinity, duration: 0.7, ease: 'easeInOut' }}
            className="text-cyber-cyan flex items-center gap-2 mt-2"
          >
            <span>❯</span>
            <span className="inline-block w-2 h-4 bg-cyber-cyan/80" />
          </motion.div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Status bar */}
      <div className="flex items-center justify-between px-4 py-1.5 border-t border-cyber-cyan/10 bg-black/30 flex-shrink-0">
        <span className="text-[10px] font-mono text-cyber-muted/50">cipherguard@local:~</span>
        <div className="flex items-center gap-4 text-[10px] font-mono text-cyber-muted/50">
          <span>{lines.length} lines</span>
          <span>UTF-8</span>
          <span className={running ? 'text-cyber-green' : 'text-cyber-muted/40'}>
            {running ? '● EXEC' : '○ IDLE'}
          </span>
        </div>
      </div>
    </motion.div>
  )
}
