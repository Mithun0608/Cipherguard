import { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Radio, Play, Square, Zap, Shield, AlertTriangle, CheckCircle, Clock, Hash, ArrowRight, ToggleLeft, ToggleRight, Database, XCircle } from 'lucide-react'
import { Badge } from '../components/ui/Badges'
import { generateDataset } from '../services/api'

const API = 'http://127.0.0.1:8000/api/v1'

const ALGORITHMS = ['plaintext','md5','sha1','sha256','salted_sha256','bcrypt','argon2id']
const ATTACKS    = ['dictionary','brute_force','rainbow_table','hybrid']

const ALGO_COLOR = {
  plaintext:'#ff3366', md5:'#ff3366', sha1:'#ff8c00',
  sha256:'#ffd700', salted_sha256:'#00f5ff', bcrypt:'#8b5cf6', argon2id:'#00ff88'
}

const STATUS_CFG = {
  waiting:   { color:'text-cyber-muted',   dot:'bg-cyber-muted/40',  label:'Waiting'   },
  attacking: { color:'text-yellow-400',    dot:'bg-yellow-400 animate-pulse', label:'Attacking' },
  cracked:   { color:'text-cyber-red',     dot:'bg-cyber-red',       label:'CRACKED'   },
  failed:    { color:'text-cyber-green',   dot:'bg-cyber-green',     label:'Resisted'  },
  timeout:   { color:'text-yellow-400',    dot:'bg-yellow-400',      label:'Timeout'   },
}

const PIPE_STAGES = ['Generate','Hash','Compare','Result']

function PipelineViz({ stage, guess, match }) {
  const stageIdx = { generate:0, load_wordlist:0, generate_mutations:0, init:0,
                     hash:1, build_table:1, lookup:1,
                     compare:2, read:2,
                     match:3, done:3 }
  const active = stageIdx[stage] ?? 0
  return (
    <div className="flex items-center gap-1 justify-center py-2">
      {PIPE_STAGES.map((s, i) => (
        <div key={s} className="flex items-center gap-1">
          <motion.div
            animate={{ scale: active === i ? [1, 1.15, 1] : 1, opacity: active === i ? 1 : 0.35 }}
            transition={{ repeat: active === i ? Infinity : 0, duration: 0.8 }}
            className={`px-2 py-1 rounded text-[10px] font-mono border ${
              active === i
                ? match ? 'border-cyber-green/60 bg-cyber-green/10 text-cyber-green'
                        : 'border-cyber-cyan/60 bg-cyber-cyan/10 text-cyber-cyan'
                : 'border-cyber-border/30 text-cyber-muted/40'
            }`}
          >{s}</motion.div>
          {i < 3 && <ArrowRight size={10} className={active > i ? 'text-cyber-cyan' : 'text-cyber-muted/20'} />}
        </div>
      ))}
    </div>
  )
}

function TargetRow({ target, status, crackedPassword, crackMs }) {
  const cfg = STATUS_CFG[status] || STATUS_CFG.waiting
  const color = ALGO_COLOR[target.algorithm] || '#00f5ff'
  return (
    <motion.tr layout initial={{ opacity:0 }} animate={{ opacity:1 }}
      className={status === 'cracked' ? 'bg-cyber-red/5' : status === 'attacking' ? 'bg-yellow-400/3' : ''}>
      <td className="font-mono text-[11px] text-cyber-muted px-3 py-1.5">{target.id}</td>
      <td className="px-3 py-1.5">
        <span className="text-[11px] font-mono" style={{color}}>{target.algorithm}</span>
      </td>
      <td className="px-3 py-1.5 font-mono text-[10px] text-cyber-muted/60 max-w-[120px] truncate">
        {target.hash_value?.slice(0,18)}…
      </td>
      <td className="px-3 py-1.5">
        <Badge variant={target.strength_category === 'weak' ? 'red' : target.strength_category === 'strong' ? 'green' : 'yellow'}>
          {target.strength_category || 'N/A'}
        </Badge>
      </td>
      <td className="px-3 py-1.5">
        <div className="flex items-center gap-1.5">
          <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${cfg.dot}`} />
          <span className={`text-[11px] font-mono ${cfg.color}`}>{cfg.label}</span>
        </div>
      </td>
      <td className="px-3 py-1.5 font-mono text-[11px] text-cyber-red font-bold">
        {crackedPassword || '—'}
      </td>
      <td className="px-3 py-1.5 font-mono text-[10px] text-cyber-muted">
        {crackMs ? `${crackMs}ms` : '—'}
      </td>
    </motion.tr>
  )
}

function TimelineItem({ ev, t0 }) {
  const elapsed = ((ev.ts - t0) / 1000).toFixed(2)
  const cfg = {
    init:           { color:'text-cyber-cyan',   icon:'⚡', bg:'bg-cyber-cyan/5'  },
    target_list:    { color:'text-cyber-cyan',   icon:'📋', bg:'bg-cyber-cyan/5'  },
    match:          { color:'text-cyber-red',    icon:'🔓', bg:'bg-cyber-red/10'  },
    algo_complete:  { color:'text-cyber-green',  icon:'✅', bg:'bg-cyber-green/5' },
    done:           { color:'text-cyber-green',  icon:'🏁', bg:'bg-cyber-green/10'},
    timeout:        { color:'text-yellow-400',   icon:'⏱', bg:'bg-yellow-400/5'  },
    attempt:        { color:'text-cyber-muted',  icon:'→',  bg:''                 },
    stats:          { color:'text-cyber-purple', icon:'📊', bg:''                 },
    target_status:  { color:'text-cyber-muted',  icon:'·',  bg:''                 },
    default:        { color:'text-cyber-muted',  icon:'·',  bg:''                 },
  }[ev.type] || { color:'text-cyber-muted', icon:'·', bg:'' }

  let text = ''
  switch(ev.type) {
    case 'init':          text = `Attack initialized — ${ev.algorithm} × ${ev.attack_type}`; break
    case 'target_list':   text = `Loaded ${ev.targets?.length} targets | space: ${ev.search_space}`; break
    case 'attempt':       text = `Trying: "${ev.guess}" (attempt #${ev.attempt_num})`; break
    case 'match':         text = `🔴 CRACKED #${ev.target_id} → "${ev.plain_password}" (${ev.crack_time_ms}ms)`; break
    case 'algo_complete': text = `${ev.algo} complete — ${ev.cracked}/${ev.total} cracked in ${(ev.elapsed_ms/1000).toFixed(2)}s`; break
    case 'stats':         text = `Speed: ${Number(ev.attempts_per_sec).toLocaleString()}/s | ${ev.cracked}/${ev.total} cracked`; break
    case 'target_status': text = `Target #${ev.target_id} → ${ev.status}${ev.plain_password ? ` ("${ev.plain_password}")` : ''}`; break
    case 'done':          text = 'Attack session complete'; break
    default:              text = JSON.stringify(ev).slice(0,80)
  }

  if (ev.type === 'attempt' && ev.attempt_num % 10 !== 0) return null // throttle attempt display

  return (
    <motion.div initial={{opacity:0,x:-8}} animate={{opacity:1,x:0}}
      className={`flex items-start gap-2 py-1 px-2 rounded text-[10px] font-mono ${cfg.bg}`}>
      <span className="text-cyber-muted/40 w-12 flex-shrink-0">[+{elapsed}s]</span>
      <span className="flex-shrink-0">{cfg.icon}</span>
      <span className={cfg.color}>{text}</span>
    </motion.div>
  )
}

function MatchCard({ ev }) {
  return (
    <motion.div initial={{opacity:0,scale:0.9,y:12}} animate={{opacity:1,scale:1,y:0}}
      className="glass-card p-4 border border-cyber-red/50 bg-cyber-red/5">
      <div className="flex items-center gap-2 mb-2">
        <AlertTriangle size={14} className="text-cyber-red animate-pulse" />
        <span className="text-cyber-red text-xs font-bold font-mono">PASSWORD CRACKED</span>
      </div>
      <div className="grid grid-cols-2 gap-2 text-[10px] font-mono">
        <div><span className="text-cyber-muted">Algorithm: </span><span className="text-yellow-400">{ev.algo}</span></div>
        <div><span className="text-cyber-muted">Time: </span><span className="text-cyber-cyan">{ev.crack_time_ms}ms</span></div>
        <div className="col-span-2">
          <span className="text-cyber-muted">Password: </span>
          <span className="text-cyber-red font-bold">"{ev.plain_password}"</span>
        </div>
        <div className="col-span-2 truncate">
          <span className="text-cyber-muted">Hash: </span>
          <span className="text-cyber-muted/50">{ev.stored_hash?.slice(0,32)}…</span>
        </div>
      </div>
    </motion.div>
  )
}

export default function LiveAttack() {
  const [algo,      setAlgo]      = useState('md5')
  const [attack,    setAttack]    = useState('dictionary')
  const [limit,     setLimit]     = useState(20)
  const [timeout,   _setTimeout]  = useState(60)
  const [demoMode,  setDemoMode]  = useState(false)
  const [streaming, setStreaming] = useState(false)
  const [genBusy,   setGenBusy]   = useState(false)

  // Live data
  const [targets,     setTargets]     = useState([])
  const [targetData,  setTargetData]  = useState({})   // id → {status,crackedPassword,crackMs}
  const [guesses,     setGuesses]     = useState([])   // last 60 attempts
  const [timeline,    setTimeline]    = useState([])
  const [matches,     setMatches]     = useState([])
  const [stats,       setStats]       = useState({attempts:0,cracked:0,total:0,aps:0,elapsed:0})
  const [pipeState,   setPipeState]   = useState({stage:'init',guess:'',match:false})
  const [done,        setDone]        = useState(false)
  const [error,       setError]       = useState('')

  const esRef       = useRef(null)
  const t0Ref       = useRef(null)
  const tlRef       = useRef(null)
  const gRef        = useRef(null)
  const streamingRef = useRef(false)

  // Auto-scroll timeline
  useEffect(() => { tlRef.current?.scrollTo({top:9999,behavior:'smooth'}) }, [timeline])
  useEffect(() => { gRef.current?.scrollTo({top:9999,behavior:'smooth'})  }, [guesses])

  const stop = useCallback(() => {
    esRef.current?.close()
    esRef.current = null
    streamingRef.current = false
    setStreaming(false)
  }, [])

  const start = useCallback(() => {
    stop()
    setDone(false)
    setError('')
    setTargets([])
    setTargetData({})
    setGuesses([])
    setTimeline([])
    setMatches([])
    setStats({attempts:0,cracked:0,total:0,aps:0,elapsed:0})
    setPipeState({stage:'init',guess:'',match:false})
    t0Ref.current = null

    const params = new URLSearchParams({
      attack_type: attack, algorithm: algo,
      target_limit: limit, timeout_sec: timeout,
      demo_mode: demoMode,
    })
    const es = new EventSource(`${API}/stream-attack?${params}`)
    esRef.current = es
    streamingRef.current = true
    setStreaming(true)

    es.onmessage = (e) => {
      const ev = JSON.parse(e.data)
      if (!t0Ref.current && ev.ts) t0Ref.current = ev.ts

      setTimeline(p => [...p.slice(-200), ev])

      switch(ev.type) {
        case 'target_list':
          setTargets(ev.targets || [])
          setTargetData(Object.fromEntries((ev.targets||[]).map(t => [t.id, {status:'waiting'}])))
          break
        case 'attempt':
          setGuesses(p => [...p.slice(-59), ev.guess])
          setPipeState({stage:'hash', guess:ev.guess, match:false})
          break
        case 'pipeline':
          setPipeState({stage:ev.stage, guess:ev.guess||'', match:!!ev.match, note:ev.note})
          break
        case 'match':
          setMatches(p => [ev, ...p.slice(0,19)])
          setTargetData(p => ({...p, [ev.target_id]:{status:'cracked',crackedPassword:ev.plain_password,crackMs:ev.crack_time_ms}}))
          break
        case 'target_status':
          setTargetData(p => ({...p, [ev.target_id]:{
            ...p[ev.target_id], status:ev.status,
            crackedPassword:ev.plain_password||p[ev.target_id]?.crackedPassword,
            crackMs:ev.crack_time_ms||p[ev.target_id]?.crackMs
          }}))
          break
        case 'stats':
          setStats({attempts:ev.attempts,cracked:ev.cracked,total:ev.total,aps:ev.attempts_per_sec,elapsed:ev.elapsed_ms})
          break
        case 'algo_complete':
          setStats(p => ({...p,cracked:ev.cracked,total:ev.total,attempts:ev.attempts||p.attempts}))
          break
        case 'done':
          setDone(true)
          setStreaming(false)
          es.close()
          break
        case 'error':
          setError(ev.message || 'Attack failed. Make sure a dataset has been generated first.')
          setTimeline(p => [...p, {type:'error', ts:Date.now(), message:ev.message}])
          setStreaming(false)
          es.close()
          break
      }
    }
    es.onerror = (e) => {
      console.error('[SSE] Connection error:', e)
      if (streamingRef.current) {
        setError('Connection to attack stream failed. Make sure the backend is running and a dataset has been generated first (click Gen Dataset).')
      }
      streamingRef.current = false
      setStreaming(false)
      es.close()
    }
  }, [algo, attack, limit, timeout, demoMode, stop])

  useEffect(() => () => stop(), [stop])

  const crackedCount = Object.values(targetData).filter(t => t.status === 'cracked').length
  const totalTargets = targets.length
  const crackRate    = totalTargets > 0 ? Math.round(crackedCount/totalTargets*100) : 0

  const genDataset = async () => {
    setGenBusy(true)
    setError('')
    try {
      // Use sample_size=15 — bcrypt/argon2id hash 15 passwords in ~5-10s
      await generateDataset({ sample_size: 15, clear_existing: true })
      setError('')
    } catch(e) {
      setError(`Dataset generation failed: ${e.message}. Try running: POST /api/v1/generate-dataset from the Experiment page.`)
    }
    setGenBusy(false)
  }

  return (
    <div className="page-container space-y-4">

      {/* ── Header ──────────────────────────────────────────── */}
      <div className="glass-card p-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 mr-2">
            <Radio size={18} className={`${streaming ? 'text-cyber-red animate-pulse' : 'text-cyber-muted'}`} />
            <span className="text-sm font-bold text-cyber-text">Live Attack Visualizer</span>
            {streaming && <Badge variant="red">LIVE</Badge>}
            {done && !streaming && <Badge variant="green">COMPLETE</Badge>}
            {error && !streaming && <Badge variant="red">ERROR</Badge>}
          </div>

          {/* Algorithm */}
          <select value={algo} onChange={e=>setAlgo(e.target.value)} disabled={streaming}
            className="cyber-input text-xs py-1.5 px-3 w-36">
            {ALGORITHMS.map(a => <option key={a} value={a}>{a}</option>)}
          </select>

          {/* Attack */}
          <select value={attack} onChange={e=>setAttack(e.target.value)} disabled={streaming}
            className="cyber-input text-xs py-1.5 px-3 w-36">
            {ATTACKS.map(a => <option key={a} value={a}>{a.replace(/_/g,' ')}</option>)}
          </select>

          {/* Limit */}
          <select value={limit} onChange={e=>setLimit(Number(e.target.value))} disabled={streaming}
            className="cyber-input text-xs py-1.5 px-3 w-24">
            {[10,20,30,50].map(n=><option key={n} value={n}>{n} targets</option>)}
          </select>

          {/* Timeout */}
          <select value={timeout} onChange={e=>_setTimeout(Number(e.target.value))} disabled={streaming}
            className="cyber-input text-xs py-1.5 px-3 w-24">
            {[15,30,60,120].map(n=><option key={n} value={n}>{n}s</option>)}
          </select>

          {/* Demo mode */}
          {attack === 'brute_force' && (
            <button onClick={()=>setDemoMode(p=>!p)} disabled={streaming}
              className="flex items-center gap-1.5 text-xs font-mono text-cyber-muted hover:text-cyber-green transition-colors">
              {demoMode ? <ToggleRight size={16} className="text-cyber-green"/> : <ToggleLeft size={16}/>}
              Demo
            </button>
          )}

          <div className="ml-auto flex gap-2">
            <button onClick={genDataset} disabled={streaming||genBusy}
              className="btn-purple py-1.5 px-3 text-xs disabled:opacity-40 flex items-center gap-1">
              <Database size={13}/>
              {genBusy ? <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-cyber-purple animate-pulse"/> Generating (may take ~15s)…</span> : 'Gen Dataset'}
            </button>
            {streaming
              ? <button onClick={stop}
                  className="flex items-center gap-1.5 py-1.5 px-3 text-xs font-mono font-bold rounded-xl border border-cyber-red/50 bg-cyber-red/10 text-cyber-red hover:bg-cyber-red/20 transition-all">
                  <Square size={13}/> Stop
                </button>
              : <button onClick={start} disabled={genBusy}
                  className="btn-solid-cyan py-1.5 px-3 text-xs flex items-center gap-1 disabled:opacity-40">
                  <Play size={13}/> Launch
                </button>
            }
          </div>
        </div>

        {/* Error banner */}
        <AnimatePresence>
          {error && !streaming && (
            <motion.div initial={{opacity:0,height:0}} animate={{opacity:1,height:'auto'}} exit={{opacity:0,height:0}}
              className="mt-3 pt-3 border-t border-cyber-red/30 flex items-start gap-2">
              <XCircle size={15} className="text-cyber-red flex-shrink-0 mt-0.5"/>
              <div className="flex-1">
                <p className="text-xs font-bold text-cyber-red">Attack Error</p>
                <p className="text-[11px] font-mono text-cyber-muted mt-0.5">{error}</p>
                <p className="text-[10px] font-mono text-yellow-400 mt-1">→ Click <strong>Gen Dataset</strong> first to populate target hashes, then Launch again.</p>
              </div>
              <button onClick={()=>setError('')} className="text-cyber-muted hover:text-cyber-red text-xs">✕</button>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Stats bar */}
        {(streaming || done) && (
          <motion.div initial={{opacity:0,height:0}} animate={{opacity:1,height:'auto'}}
            className="grid grid-cols-5 gap-3 mt-3 pt-3 border-t border-cyber-border/30">
            {[
              {label:'Cracked',  val:`${crackedCount}/${totalTargets}`,       col: crackedCount>0?'text-cyber-red':'text-cyber-green'},
              {label:'Crack Rate',val:`${crackRate}%`,                        col: crackRate>50?'text-cyber-red':'text-cyber-green'},
              {label:'Attempts', val:Number(stats.attempts).toLocaleString(), col:'text-cyber-purple'},
              {label:'Speed',    val:`${Number(stats.aps).toLocaleString()}/s`, col:'text-cyber-cyan'},
              {label:'Elapsed',  val:`${(stats.elapsed/1000).toFixed(1)}s`,   col:'text-cyber-muted'},
            ].map(({label,val,col})=>(
              <div key={label} className="text-center">
                <p className={`text-lg font-extrabold font-mono ${col}`}>{val}</p>
                <p className="text-[10px] text-cyber-muted">{label}</p>
              </div>
            ))}
          </motion.div>
        )}
      </div>

      {/* ── Pipeline ─────────────────────────────────────────── */}
      {(streaming || done) && (
        <div className="glass-card p-3">
          <p className="text-[10px] font-mono text-cyber-muted mb-1">ATTACK PIPELINE</p>
          <PipelineViz stage={pipeState.stage} guess={pipeState.guess} match={pipeState.match} />
          {pipeState.guess && (
            <p className="text-center text-[11px] font-mono text-cyber-cyan mt-1">
              Current guess: <span className="text-white font-bold">"{pipeState.guess}"</span>
              {pipeState.note && <span className="text-cyber-muted ml-2">— {pipeState.note}</span>}
            </p>
          )}
        </div>
      )}

      {/* ── Main 3-col layout ────────────────────────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4" style={{minHeight:'480px'}}>

        {/* Target Table */}
        <div className="glass-card overflow-hidden flex flex-col xl:col-span-1">
          <div className="px-4 py-3 border-b border-cyber-border/30 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Hash size={13} className="text-cyber-cyan"/>
              <span className="text-xs font-bold text-cyber-text">Target Hashes</span>
            </div>
            <Badge variant="cyan">{targets.length}</Badge>
          </div>
          <div className="overflow-auto flex-1">
            <table className="w-full text-left">
              <thead className="sticky top-0 bg-cyber-surface/90 backdrop-blur-sm">
                <tr className="text-[9px] font-mono text-cyber-muted/60 uppercase">
                  {['ID','Algo','Hash','Category','Status','Password','Time'].map(h=>(
                    <th key={h} className="px-3 py-2">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {targets.map(t => (
                  <TargetRow key={t.id} target={t}
                    status={targetData[t.id]?.status || 'waiting'}
                    crackedPassword={targetData[t.id]?.crackedPassword}
                    crackMs={targetData[t.id]?.crackMs}
                  />
                ))}
                {targets.length === 0 && (
                  <tr><td colSpan={7} className="px-4 py-8 text-center text-xs text-cyber-muted font-mono">
                    No targets loaded — launch an attack to begin
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Center — Guess Stream + Matches */}
        <div className="flex flex-col gap-4">
          {/* Live guess stream */}
          <div className="glass-card flex flex-col" style={{minHeight:'240px'}}>
            <div className="px-4 py-3 border-b border-cyber-border/30 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Zap size={13} className="text-cyber-red"/>
                <span className="text-xs font-bold text-cyber-text">Password Guess Stream</span>
                {streaming && <span className="w-1.5 h-1.5 rounded-full bg-cyber-red animate-pulse"/>}
              </div>
              <span className="text-[10px] font-mono text-cyber-muted">{guesses.length} shown</span>
            </div>
            <div ref={gRef} className="flex-1 overflow-y-auto p-3 space-y-0.5 font-mono text-[11px]">
              {guesses.map((g, i) => (
                <motion.div key={i} initial={{opacity:0,x:-4}} animate={{opacity:1,x:0}}
                  className={`py-0.5 px-2 rounded ${i === guesses.length-1 ? 'bg-cyber-cyan/10 text-cyber-cyan' : 'text-cyber-muted/60'}`}>
                  <span className="text-cyber-muted/30 mr-2">→</span>{g}
                </motion.div>
              ))}
              {guesses.length === 0 && (
                <p className="text-center text-cyber-muted/40 mt-8">Awaiting attack...</p>
              )}
            </div>
          </div>

          {/* Match cards */}
          <div className="glass-card flex flex-col overflow-hidden" style={{minHeight:'220px'}}>
            <div className="px-4 py-3 border-b border-cyber-border/30 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AlertTriangle size={13} className="text-cyber-red"/>
                <span className="text-xs font-bold text-cyber-text">Cracked Passwords</span>
              </div>
              {matches.length > 0 && <Badge variant="red">{matches.length} cracked</Badge>}
            </div>
            <div className="flex-1 overflow-y-auto p-3 space-y-2">
              <AnimatePresence>
                {matches.slice(0,8).map((m,i) => <MatchCard key={`${m.target_id}-${i}`} ev={m}/>)}
              </AnimatePresence>
              {matches.length === 0 && (
                <div className="flex flex-col items-center justify-center h-24 text-cyber-muted/30">
                  <Shield size={24}/>
                  <p className="text-[11px] font-mono mt-2">No cracks yet</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Timeline */}
        <div className="glass-card flex flex-col">
          <div className="px-4 py-3 border-b border-cyber-border/30 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Clock size={13} className="text-cyber-purple"/>
              <span className="text-xs font-bold text-cyber-text">Attack Timeline</span>
            </div>
            <span className="text-[10px] font-mono text-cyber-muted">{timeline.length} events</span>
          </div>
          <div ref={tlRef} className="flex-1 overflow-y-auto p-2 space-y-0.5">
            {timeline.map((ev, i) => (
              <TimelineItem key={i} ev={ev} t0={t0Ref.current || ev.ts}/>
            ))}
            {timeline.length === 0 && (
              <div className="flex items-center justify-center h-24">
                <p className="text-[11px] font-mono text-cyber-muted/40">Timeline will appear here</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Done banner ──────────────────────────────────────── */}
      <AnimatePresence>
        {done && (
          <motion.div initial={{opacity:0,y:12}} animate={{opacity:1,y:0}} exit={{opacity:0}}
            className={`glass-card p-4 border ${crackedCount > 0 ? 'border-cyber-red/50' : 'border-cyber-green/50'}`}>
            <div className="flex items-center gap-3">
              {crackedCount > 0
                ? <AlertTriangle size={18} className="text-cyber-red"/>
                : <CheckCircle size={18} className="text-cyber-green"/>}
              <div>
                <p className={`text-sm font-bold ${crackedCount > 0 ? 'text-cyber-red' : 'text-cyber-green'}`}>
                  {crackedCount > 0
                    ? `${crackedCount}/${totalTargets} passwords COMPROMISED (${crackRate}%)`
                    : `All ${totalTargets} passwords resisted the attack`}
                </p>
                <p className="text-[11px] font-mono text-cyber-muted">
                  {algo.toUpperCase()} × {attack.replace(/_/g,' ')} — {(stats.elapsed/1000).toFixed(2)}s | {Number(stats.attempts).toLocaleString()} attempts
                </p>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

    </div>
  )
}
