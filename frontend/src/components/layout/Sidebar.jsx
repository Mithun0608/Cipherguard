import { useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import {
  LayoutDashboard, FlaskConical, Swords, GitCompare,
  ShieldCheck, Layers, Radiation, FileText, Settings,
  ChevronLeft, ChevronRight, Shield, Menu, X
} from 'lucide-react'

const NAV = [
  { to: '/dashboard',  icon: LayoutDashboard, label: 'Dashboard',        sub: 'Mission Control',   color: 'cyan' },
  { to: '/experiment', icon: FlaskConical,     label: 'Experiment',       sub: 'Attack Runner',     color: 'purple' },
  { to: '/attacks',    icon: Swords,           label: 'Attack Analysis',  sub: 'Deep Dive',         color: 'red' },
  { to: '/algorithms', icon: GitCompare,       label: 'Algorithms',       sub: 'Comparison',        color: 'cyan' },
  { to: '/scorecard',  icon: ShieldCheck,      label: 'Scorecard',        sub: 'Security Rank',     color: 'green' },
  { to: '/salting',    icon: Layers,           label: 'Salting',          sub: 'Visualizer',        color: 'purple' },
  { to: '/breach',     icon: Radiation,        label: 'Breach Sim',       sub: 'Simulation',        color: 'red' },
  { to: '/logs',       icon: FileText,         label: 'Logs & Reports',   sub: 'Enterprise View',   color: 'cyan' },
  { to: '/settings',   icon: Settings,         label: 'Settings',         sub: 'Configuration',     color: 'cyan' },
]

const COLOR_MAP = {
  cyan:   { text: 'text-cyber-cyan',   activeBg: 'bg-cyber-cyan/10',   activeBorder: 'border-cyber-cyan/40',   dot: 'bg-cyber-cyan',   glow: 'shadow-glow-cyan' },
  purple: { text: 'text-cyber-purple', activeBg: 'bg-cyber-purple/10', activeBorder: 'border-cyber-purple/40', dot: 'bg-cyber-purple', glow: 'shadow-glow-purple' },
  green:  { text: 'text-cyber-green',  activeBg: 'bg-cyber-green/10',  activeBorder: 'border-cyber-green/40',  dot: 'bg-cyber-green',  glow: 'shadow-glow-green' },
  red:    { text: 'text-cyber-red',    activeBg: 'bg-cyber-red/10',    activeBorder: 'border-cyber-red/40',    dot: 'bg-cyber-red',    glow: 'shadow-glow-red' },
}

export default function Sidebar() {
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const location = useLocation()

  const SidebarContent = ({ isMobile = false }) => (
    <div className={`flex flex-col h-full ${isMobile ? 'w-64' : ''}`}>
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 py-5 border-b border-cyber-border/40 min-h-[68px]">
        <div className="relative flex-shrink-0">
          <div className="w-9 h-9 rounded-xl bg-cyber-cyan/10 border border-cyber-cyan/40 flex items-center justify-center shadow-glow-cyan">
            <Shield size={18} className="text-cyber-cyan" />
          </div>
          <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-cyber-green border-2 border-cyber-bg animate-pulse" />
        </div>
        <AnimatePresence>
          {(!collapsed || isMobile) && (
            <motion.div
              initial={{ opacity: 0, x: -10, width: 0 }}
              animate={{ opacity: 1, x: 0, width: 'auto' }}
              exit={{ opacity: 0, x: -10, width: 0 }}
              transition={{ duration: 0.2 }}
              className="overflow-hidden whitespace-nowrap"
            >
              <p className="text-sm font-extrabold text-cyber-gradient tracking-wide">CipherGuard</p>
              <p className="text-[10px] text-cyber-muted font-mono">v3.0 · Phase III</p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Nav label */}
      <AnimatePresence>
        {(!collapsed || isMobile) && (
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="px-4 pt-5 pb-2 text-[10px] font-mono text-cyber-muted/50 uppercase tracking-[0.15em]"
          >
            Navigation
          </motion.p>
        )}
      </AnimatePresence>

      {/* Nav items */}
      <nav className="flex-1 px-2 space-y-0.5 overflow-y-auto overflow-x-hidden pb-4">
        {NAV.map(({ to, icon: Icon, label, sub, color }) => {
          const isActive = location.pathname === to || (to !== '/dashboard' && location.pathname.startsWith(to))
          const c = COLOR_MAP[color]
          return (
            <NavLink key={to} to={to} title={collapsed && !isMobile ? label : undefined}
              onClick={() => setMobileOpen(false)}>
              <motion.div
                whileHover={{ x: (collapsed && !isMobile) ? 0 : 3 }}
                className={`
                  relative flex items-center gap-3 px-3 py-2.5 rounded-xl cursor-pointer
                  transition-all duration-200 group
                  ${isActive
                    ? `${c.activeBg} border ${c.activeBorder} ${c.text} ${c.glow}`
                    : 'text-cyber-muted border border-transparent hover:text-cyber-text hover:bg-cyber-card/40'}
                `}
              >
                {/* Active left indicator */}
                {isActive && (
                  <motion.div
                    layoutId="activeBar"
                    className={`absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-6 ${c.dot} rounded-full`}
                    style={{ filter: `drop-shadow(0 0 6px currentColor)` }}
                  />
                )}

                <Icon size={18} className={`flex-shrink-0 transition-colors ${isActive ? c.text : 'group-hover:text-cyber-text'}`} />

                <AnimatePresence>
                  {(!collapsed || isMobile) && (
                    <motion.div
                      initial={{ opacity: 0, width: 0 }}
                      animate={{ opacity: 1, width: 'auto' }}
                      exit={{ opacity: 0, width: 0 }}
                      className="overflow-hidden whitespace-nowrap flex-1 min-w-0"
                    >
                      <p className="text-sm font-medium leading-tight">{label}</p>
                      <p className={`text-[10px] font-mono ${isActive ? `${c.text} opacity-70` : 'text-cyber-muted/50'}`}>{sub}</p>
                    </motion.div>
                  )}
                </AnimatePresence>

                {isActive && (!collapsed || isMobile) && (
                  <motion.div
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    className={`w-1.5 h-1.5 rounded-full ${c.dot} flex-shrink-0 animate-pulse`}
                  />
                )}
              </motion.div>
            </NavLink>
          )
        })}
      </nav>

      {/* Bottom status */}
      <AnimatePresence>
        {(!collapsed || isMobile) && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="p-3 mx-2 mb-3 rounded-xl bg-cyber-card/50 border border-cyber-border/30"
          >
            <div className="flex items-center gap-2 mb-2">
              <span className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse" />
              <span className="text-[10px] font-mono text-cyber-green">SYSTEM ONLINE</span>
            </div>
            <div className="grid grid-cols-2 gap-1 text-[9px] font-mono text-cyber-muted">
              <span>7 algorithms</span>
              <span>4 attacks</span>
              <span>SQLite DB</span>
              <span>FastAPI</span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Collapse toggle (desktop only) */}
      {!isMobile && (
        <div className="p-2 border-t border-cyber-border/30">
          <button
            onClick={() => setCollapsed(p => !p)}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-cyber-muted
                       hover:text-cyber-cyan hover:bg-cyber-cyan/10 transition-all duration-200 text-xs font-mono"
          >
            {collapsed
              ? <ChevronRight size={15} />
              : <><ChevronLeft size={15} /><span>Collapse</span></>
            }
          </button>
        </div>
      )}

      {/* Animated right border glow */}
      <div className="absolute right-0 top-0 bottom-0 w-px bg-gradient-to-b from-transparent via-cyber-cyan/20 to-transparent" />
    </div>
  )

  return (
    <>
      {/* Mobile menu button */}
      <button
        onClick={() => setMobileOpen(true)}
        className="md:hidden fixed top-4 left-4 z-50 p-2 rounded-lg bg-cyber-card border border-cyber-border text-cyber-muted hover:text-cyber-cyan transition-colors"
      >
        <Menu size={18} />
      </button>

      {/* Mobile drawer */}
      <AnimatePresence>
        {mobileOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setMobileOpen(false)}
              className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 md:hidden"
            />
            <motion.aside
              initial={{ x: -280 }}
              animate={{ x: 0 }}
              exit={{ x: -280 }}
              transition={{ type: 'spring', damping: 25, stiffness: 200 }}
              className="fixed left-0 top-0 bottom-0 w-64 bg-cyber-surface border-r border-cyber-border z-50 md:hidden overflow-hidden"
            >
              <button
                onClick={() => setMobileOpen(false)}
                className="absolute top-4 right-4 p-1.5 rounded-lg text-cyber-muted hover:text-cyber-red transition-colors z-10"
              >
                <X size={16} />
              </button>
              <SidebarContent isMobile />
            </motion.aside>
          </>
        )}
      </AnimatePresence>

      {/* Desktop sidebar */}
      <motion.aside
        animate={{ width: collapsed ? 68 : 224 }}
        transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] }}
        className="hidden md:relative md:flex md:flex-col h-screen bg-cyber-surface border-r border-cyber-border/60
                   z-50 overflow-hidden flex-shrink-0"
      >
        <SidebarContent />
      </motion.aside>
    </>
  )
}
