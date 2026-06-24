import { useState, useEffect, useRef, useCallback } from 'react'
import cytoscape from 'cytoscape'

const API = 'http://localhost:8000'

const DOMAIN_COLORS: Record<string, string> = {
  cloud: '#2E75B6', code: '#375623', k8s: '#1A6B6B',
  iam: '#5B2D8E', api: '#C55A11', data_pipeline: '#7F6000',
  container: '#1F3864', mobile: '#C00000', ai_llm: '#595959',
  finding: '#8b949e', unknown: '#444',
}
const SUBTYPE_COLORS: Record<string, string> = {
  network_firewall: '#B84A00',
  application_firewall: '#990000',
  workload_firewall: '#6B5000',
}
const EDGE_COLORS: Record<string, string> = {
  E_invoke:    '#4A9EFF',
  E_contain:   '#555',
  E_trust:     '#9B6DFF',
  E_data_flow: '#3FB950',
  E_taint_path:'#F85149',
  E_governs:   '#D29922',
  E_owns:      '#8B949E',
}
const POSTURE_INFO: Record<string, { color: string; label: string }> = {
  unprotected:                   { color: '#F85149', label: 'Unprotected' },
  declared_permissive:           { color: '#D29922', label: 'Permissive' },
  declared_restrictive:          { color: '#388BFD', label: 'Restrictive' },
  declared_restrictive_with_waf: { color: '#3FB950', label: 'Restrictive + WAF' },
  inherited_only:                { color: '#D29922', label: 'Inherited' },
  unknown:                       { color: '#555',    label: 'Unknown' },
}

const DOMAINS = ['cloud','code','k8s','iam','api','container','mobile','ai_llm']

export default function App() {
  const [view, setView]                 = useState<'graph'|'upload'|'findings'|'review'|'stats'>('graph')
  const [stats, setStats]               = useState<any>(null)
  const [nodes, setNodes]               = useState<any[]>([])
  const [edges, setEdges]               = useState<any[]>([])
  const [selected, setSelected]         = useState<any>(null)
  const [selectedEdge, setSelectedEdge] = useState<any>(null)
  const [uploading, setUploading]       = useState(false)
  const [uploadResult, setUploadResult] = useState<any>(null)
  const [findings, setFindings]         = useState<any[]>([])
  const [findingStats, setFindingStats] = useState<any>(null)
  const [singleFinding, setSingleFinding] = useState('')
  const [reviewItems, setReviewItems]     = useState<any[]>([])
  const [reviewStats, setReviewStats]     = useState<any>(null)
  const [reviewDeciding, setReviewDeciding] = useState<string | null>(null)
  const [activeDomains, setActiveDomains] = useState<Set<string>>(new Set(DOMAINS))
  const cyRef      = useRef<HTMLDivElement>(null)
  const cyInstance = useRef<any>(null)

  const fetchAll = async () => {
    try {
      const [sr, nr, er, fr, fsr, rq, rs] = await Promise.all([
        fetch(`${API}/api/v1/graph/stats`).then(r => r.json()),
        fetch(`${API}/api/v1/graph/nodes?limit=500`).then(r => r.json()),
        fetch(`${API}/api/v1/graph/edges?limit=1000`).then(r => r.json()),
        fetch(`${API}/api/v1/findings/?limit=100`).then(r => r.json()),
        fetch(`${API}/api/v1/findings/stats`).then(r => r.json()),
        fetch(`${API}/api/v1/review/queue`).then(r => r.json()),
        fetch(`${API}/api/v1/review/stats`).then(r => r.json()),
      ])
      setStats(sr); setNodes(nr.nodes||[]); setEdges(er.edges||[])
      setFindings(fr.findings||[]); setFindingStats(fsr)
      setReviewItems(rq.items||[]); setReviewStats(rs)
    } catch(e) { console.error(e) }
  }

  useEffect(() => { fetchAll() }, [])

  const buildGraph = useCallback(() => {
    if (!cyRef.current) return
    if (cyInstance.current) cyInstance.current.destroy()

    const visibleNodes = nodes.filter(n =>
      n.domain_type !== 'finding' && activeDomains.has(n.domain_type || 'unknown')
    )
    const visibleIds = new Set(visibleNodes.map(n => n.entity_id))
    const visibleEdges = edges.filter(e => visibleIds.has(e.source) && visibleIds.has(e.target))

    const elements = [
      ...visibleNodes.map(n => ({
        data: {
          id: n.entity_id,
          label: (n.name || n.entity_id?.split('::').pop() || '').slice(0, 28),
          domain: n.domain_type || 'unknown',
          subtype: n.resource_subtype,
          posture: n.firewall_posture,
          entry: n.is_entry_point,
          raw: n,
        }
      })),
      ...visibleEdges.map(e => ({
        data: {
          id: `${e.source}__${e.target}__${e.edge_type}`,
          source: e.source,
          target: e.target,
          edge_type: e.edge_type || 'E_contain',
          label: (e.edge_type || '').replace('E_', ''),
          confidence: e.confidence,
        }
      }))
    ]

    cyInstance.current = cytoscape({
      container: cyRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': (ele: any) => {
              const sub = ele.data('subtype')
              if (sub && SUBTYPE_COLORS[sub]) return SUBTYPE_COLORS[sub]
              return DOMAIN_COLORS[ele.data('domain')] || '#444'
            },
            'label': 'data(label)',
            'color': '#e0e0e0',
            'font-size': '10px',
            'font-family': 'Inter, system-ui, sans-serif',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'text-margin-y': '6px',
            'text-outline-width': '2px',
            'text-outline-color': '#0f1117',
            'width': (ele: any) => ele.data('entry') ? 44 : 30,
            'height': (ele: any) => ele.data('entry') ? 44 : 30,
            'border-width': (ele: any) => ele.data('entry') ? 3 : 1,
            'border-color': (ele: any) => ele.data('entry') ? '#FFD700' : 'rgba(255,255,255,0.15)',
            'border-opacity': 1,
            'z-index': (ele: any) => ele.data('entry') ? 10 : 1,
          }
        },
        {
          selector: 'node:selected',
          style: {
            'border-width': 3,
            'border-color': '#58A6FF',
            'z-index': 99,
          }
        },
        {
          selector: 'edge',
          style: {
            'width': 1.5,
            'line-color': (ele: any) => EDGE_COLORS[ele.data('edge_type')] || '#555',
            'target-arrow-color': (ele: any) => EDGE_COLORS[ele.data('edge_type')] || '#555',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.8,
            'curve-style': 'bezier',
            'opacity': 0.7,
            // Labels hidden by default — shown on selection only
            'label': '',
            'font-size': '9px',
            'color': '#aaa',
            'text-rotation': 'autorotate',
            'text-outline-width': '2px',
            'text-outline-color': '#0f1117',
          }
        },
        {
          selector: 'edge:selected',
          style: {
            'width': 3,
            'opacity': 1,
            'label': 'data(label)',
            'z-index': 99,
          }
        },
        {
          selector: 'node.faded',
          style: { 'opacity': 0.25 }
        },
        {
          selector: 'edge.faded',
          style: { 'opacity': 0.08 }
        },
      ],
      layout: {
        name: 'cose',
        animate: false,
        padding: 60,
        nodeRepulsion: () => 25000,
        nodeOverlap: 30,
        idealEdgeLength: () => 120,
        edgeElasticity: () => 100,
        nestingFactor: 1.2,
        gravity: 0.25,
        numIter: 1000,
        initialTemp: 1000,
        coolingFactor: 0.99,
        minTemp: 1.0,
        randomize: true,
        componentSpacing: 80,
      } as any,
    })

    cyInstance.current.on('tap', 'node', (evt: any) => {
      setSelectedEdge(null)
      const node = evt.target
      setSelected(node.data('raw'))
      // Highlight connected nodes
      cyInstance.current.elements().addClass('faded')
      node.removeClass('faded')
      node.connectedEdges().removeClass('faded')
      node.connectedEdges().connectedNodes().removeClass('faded')
    })
    cyInstance.current.on('tap', 'edge', (evt: any) => {
      setSelected(null)
      const edge = evt.target
      setSelectedEdge({
        edge_type: edge.data('edge_type'),
        label: edge.data('label'),
        confidence: edge.data('confidence'),
        source: edge.source().data('label'),
        target: edge.target().data('label'),
      })
    })
    cyInstance.current.on('tap', (evt: any) => {
      if (evt.target === cyInstance.current) {
        setSelected(null)
        setSelectedEdge(null)
        cyInstance.current.elements().removeClass('faded')
      }
    })
  }, [nodes, edges, activeDomains])

  useEffect(() => { buildGraph() }, [buildGraph])

  const zoom = (dir: number) => cyInstance.current?.zoom({ level: cyInstance.current.zoom() * (1 + dir * 0.2), renderedPosition: { x: cyRef.current!.offsetWidth/2, y: cyRef.current!.offsetHeight/2 } })
  const fit  = ()            => cyInstance.current?.fit(undefined, 40)

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>, type: string) => {
    const file = e.target.files?.[0]; if (!file) return
    setUploading(true); setUploadResult(null)
    const fd = new FormData(); fd.append('file', file)
    try {
      const r = await fetch(`${API}/api/v1/ingestion/${type}`, { method: 'POST', body: fd })
      setUploadResult(await r.json())
      await fetchAll()
    } catch(err: any) { setUploadResult({ error: err.message }) }
    setUploading(false); e.target.value = ''
  }

  const handleIngestFinding = async () => {
    try {
      const finding = JSON.parse(singleFinding)
      const r = await fetch(`${API}/api/v1/findings/ingest`, {
        method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(finding)
      })
      setUploadResult(await r.json()); await fetchAll()
    } catch(err: any) { setUploadResult({ error: err.message }) }
  }

  const toggleDomain = (d: string) => {
    setActiveDomains(prev => {
      const next = new Set(prev)
      next.has(d) ? next.delete(d) : next.add(d)
      return next
    })
  }

  const S = (label: string, color: string) => (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 10, color }}>
      <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, display: 'inline-block' }} />
      {label}
    </span>
  )

  return (
    <div style={{ display:'flex', height:'100vh', background:'#0d1117', color:'#c9d1d9', fontFamily:'Inter,system-ui,sans-serif', fontSize:13 }}>

      {/* Sidebar */}
      <div style={{ width:220, minWidth:220, background:'#161b22', borderRight:'1px solid #21262d', display:'flex', flexDirection:'column', overflow:'hidden' }}>
        <div style={{ padding:'18px 16px 12px', borderBottom:'1px solid #21262d' }}>
          <div style={{ fontSize:14, fontWeight:700, color:'#58a6ff', letterSpacing:1 }}>SATARK</div>
          <div style={{ fontSize:11, color:'#8b949e', marginTop:2 }}>Layer 1 · Prototype</div>
        </div>

        {stats && (
          <div style={{ padding:'12px 16px', borderBottom:'1px solid #21262d', fontSize:12 }}>
            <div style={{ fontSize:10, color:'#8b949e', textTransform:'uppercase', letterSpacing:1, marginBottom:6 }}>Knowledge Graph</div>
            <div style={{ display:'flex', gap:16, marginBottom:6 }}>
              <div><div style={{ fontSize:20, fontWeight:700, color:'#f0f6fc' }}>{stats.total_nodes}</div><div style={{ fontSize:10, color:'#8b949e' }}>nodes</div></div>
              <div><div style={{ fontSize:20, fontWeight:700, color:'#f0f6fc' }}>{stats.total_edges}</div><div style={{ fontSize:10, color:'#8b949e' }}>edges</div></div>
            </div>
            {Object.entries(stats.nodes_by_domain||{}).map(([d,c]:any)=>(
              <div key={d} style={{ display:'flex', justifyContent:'space-between', marginBottom:3 }}>
                <span style={{ color: DOMAIN_COLORS[d]||'#888', fontSize:11 }}>● {d}</span>
                <span style={{ color:'#8b949e', fontSize:11 }}>{c}</span>
              </div>
            ))}
            {findingStats?.total > 0 && (
              <div style={{ marginTop:8, paddingTop:8, borderTop:'1px solid #21262d' }}>
                <div style={{ fontSize:10, color:'#8b949e', textTransform:'uppercase', letterSpacing:1, marginBottom:4 }}>Findings</div>
                <div style={{ fontSize:18, fontWeight:700, color:'#f0f6fc' }}>{findingStats.total}</div>
                {findingStats.needs_review > 0 && <div style={{ fontSize:11, color:'#f85149' }}>{findingStats.needs_review} need review</div>}
              </div>
            )}
          </div>
        )}

        <nav style={{ padding:'8px', flex:1, overflowY:'auto' }}>
          {[{id:'graph',label:'⬡ Knowledge Graph'},{id:'upload',label:'↑ Ingest Asset'},{id:'findings',label:'⚠ Findings Pool'},
            {id:'review',label:'🔗 Link Review'},{id:'stats',label:'≡ Stats'}].map(item=>(
            <div key={item.id} onClick={()=>setView(item.id as any)} style={{ padding:'8px 10px', borderRadius:6, cursor:'pointer', marginBottom:2, background:view===item.id?'#1f6feb22':'transparent', color:view===item.id?'#58a6ff':'#c9d1d9', fontSize:13 }}>
              {item.label}
            </div>
          ))}
        </nav>

        {/* Edge type legend */}
        <div style={{ padding:'12px 16px', borderTop:'1px solid #21262d', display:'flex', flexDirection:'column', gap:4 }}>
          <div style={{ fontSize:10, color:'#8b949e', textTransform:'uppercase', letterSpacing:1, marginBottom:4 }}>Edge Types</div>
          {Object.entries(EDGE_COLORS).map(([k,v])=>(
            <div key={k} style={{ display:'flex', alignItems:'center', gap:6, fontSize:10 }}>
              <span style={{ width:16, height:2, background:v, display:'inline-block', borderRadius:1 }} />
              <span style={{ color:'#8b949e' }}>{k.replace('E_','')}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Main */}
      <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>

        {/* Graph view */}
        {view==='graph' && (
          <div style={{ flex:1, position:'relative', overflow:'hidden' }}>

            {/* Toolbar */}
            <div style={{ position:'absolute', top:12, left:12, zIndex:10, display:'flex', gap:6, flexWrap:'wrap', maxWidth:'calc(100% - 320px)' }}>
              {/* Zoom controls */}
              {[{label:'+', fn:()=>zoom(1)},{label:'−',fn:()=>zoom(-1)},{label:'⊡ Fit',fn:fit}].map(b=>(
                <button key={b.label} onClick={b.fn} style={{ padding:'5px 10px', background:'#161b22', border:'1px solid #30363d', borderRadius:6, color:'#c9d1d9', cursor:'pointer', fontSize:12 }}>
                  {b.label}
                </button>
              ))}
              {/* Domain filters */}
              <div style={{ width:1, background:'#30363d', margin:'0 2px' }} />
              {DOMAINS.map(d=>(
                <button key={d} onClick={()=>toggleDomain(d)} style={{
                  padding:'4px 10px', borderRadius:6, cursor:'pointer', fontSize:11, border:'1px solid',
                  background: activeDomains.has(d) ? DOMAIN_COLORS[d]+'33' : 'transparent',
                  borderColor: activeDomains.has(d) ? DOMAIN_COLORS[d] : '#30363d',
                  color: activeDomains.has(d) ? DOMAIN_COLORS[d] : '#8b949e',
                }}>
                  {d}
                </button>
              ))}
            </div>

            {/* Graph canvas */}
            <div ref={cyRef} style={{ width:'100%', height:'100%', background:'#0d1117' }} />

            {/* Empty state */}
            {nodes.filter(n=>n.domain_type!=='finding').length===0 && (
              <div style={{ position:'absolute', top:'50%', left:'50%', transform:'translate(-50%,-50%)', textAlign:'center', color:'#8b949e', pointerEvents:'none' }}>
                <div style={{ fontSize:48, marginBottom:16, opacity:.3 }}>⬡</div>
                <div style={{ fontSize:16, fontWeight:600, color:'#c9d1d9' }}>Knowledge Graph is empty</div>
                <div style={{ fontSize:13, marginTop:6 }}>Go to Ingest Asset to upload your first file</div>
              </div>
            )}

            {/* Node detail panel */}
            {selected && (
              <div style={{ position:'absolute', top:12, right:12, width:270, background:'#161b22', border:'1px solid #30363d', borderRadius:8, padding:16, fontSize:12, maxHeight:'80vh', overflowY:'auto', zIndex:10 }}>
                <div style={{ display:'flex', justifyContent:'space-between', marginBottom:12 }}>
                  <span style={{ fontWeight:700, color:'#f0f6fc', fontSize:13, wordBreak:'break-all' }}>{selected.name}</span>
                  <span onClick={()=>{ setSelected(null); cyInstance.current?.elements().removeClass('faded') }} style={{ cursor:'pointer', color:'#8b949e', marginLeft:8, flexShrink:0 }}>✕</span>
                </div>
                {selected.firewall_posture && (
                  <div style={{ marginBottom:10, padding:'4px 10px', borderRadius:4, background:'#0d1117', display:'inline-block',
                    color: POSTURE_INFO[selected.firewall_posture]?.color||'#888', fontSize:11, fontWeight:600 }}>
                    🛡 {POSTURE_INFO[selected.firewall_posture]?.label||selected.firewall_posture}
                  </div>
                )}
                {[
                  ['Domain',       selected.domain_type],
                  ['Type',         selected.node_type],
                  ['Subtype',      selected.resource_subtype],
                  ['Entry point',  selected.is_entry_point ? '✓ Yes' : 'No'],
                  ['File',         selected.file_path],
                  ['Lines',        selected.start_line ? `${selected.start_line} – ${selected.end_line}` : null],
                  ['Confidence',   selected.confidence != null ? `${(selected.confidence*100).toFixed(0)}%` : null],
                  ['Resolved by',  selected.resolved_by],
                  ['ARN',          selected.arn],
                  ['IRSA role',    selected.irsa_role_arn],
                  ['Tag: service', selected.tag_service],
                  ['IAM effect',   selected.iam_effect],
                ].filter(([,v])=>v!=null).map(([k,v])=>(
                  <div key={k as string} style={{ display:'flex', justifyContent:'space-between', marginBottom:5, paddingBottom:4, borderBottom:'1px solid #21262d' }}>
                    <span style={{ color:'#8b949e', flexShrink:0 }}>{k}</span>
                    <span style={{ color:'#c9d1d9', maxWidth:160, textAlign:'right', wordBreak:'break-all', marginLeft:8 }}>{String(v)}</span>
                  </div>
                ))}
                {selected.semantic_summary && (
                  <div style={{ marginTop:8, padding:8, background:'#0d1117', borderRadius:4, color:'#8b949e', fontSize:11, lineHeight:1.5 }}>
                    {selected.semantic_summary}
                  </div>
                )}
              </div>
            )}

            {/* Edge detail panel */}
            {selectedEdge && (
              <div style={{ position:'absolute', top:12, right:12, width:220, background:'#161b22', border:'1px solid #30363d', borderRadius:8, padding:14, fontSize:12, zIndex:10 }}>
                <div style={{ display:'flex', justifyContent:'space-between', marginBottom:10 }}>
                  <span style={{ fontWeight:600, color:EDGE_COLORS[selectedEdge.edge_type]||'#888', fontSize:12 }}>{selectedEdge.edge_type}</span>
                  <span onClick={()=>setSelectedEdge(null)} style={{ cursor:'pointer', color:'#8b949e' }}>✕</span>
                </div>
                <div style={{ color:'#c9d1d9', marginBottom:4 }}>{selectedEdge.source}</div>
                <div style={{ color:'#8b949e', fontSize:11, marginBottom:4 }}>↓ {selectedEdge.label}</div>
                <div style={{ color:'#c9d1d9' }}>{selectedEdge.target}</div>
                {selectedEdge.confidence && (
                  <div style={{ marginTop:8, fontSize:11, color:'#8b949e' }}>Confidence: {(selectedEdge.confidence*100).toFixed(0)}%</div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Upload view */}
        {view==='upload' && (
          <div style={{ flex:1, padding:32, overflowY:'auto' }}>
            <div style={{ fontSize:18, fontWeight:700, color:'#f0f6fc', marginBottom:4 }}>Ingest Asset</div>
            <div style={{ fontSize:13, color:'#8b949e', marginBottom:24 }}>Upload a ground truth file. Parsed immediately into the Knowledge Graph.</div>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12, maxWidth:660 }}>
              {[
                {type:'terraform',   label:'Terraform IaC',      ext:'.tf',   desc:'Cloud resources, security groups, WAF'},
                {type:'k8s',         label:'Kubernetes Manifest', ext:'.yaml', desc:'Deployments, Services, NetworkPolicy'},
                {type:'code/python', label:'Python Code',         ext:'.py',   desc:'Functions, classes, route handlers'},
                {type:'openapi',     label:'OpenAPI Spec',        ext:'.yaml', desc:'REST API endpoints and parameters'},
                {type:'iam',         label:'IAM Policy',          ext:'.json', desc:'AWS IAM statements with E_trust edges'},
              {type:'cicd',        label:'CI/CD Pipeline',      ext:'.yml',  desc:'GitHub Actions / GitLab CI — pipelines, jobs, steps, secret injections'},
              {type:'container',   label:'Dockerfile / Compose',ext:'',      desc:'Container images, base images, layers, exposed ports, env vars'},
              {type:'compliance',  label:'Compliance Declarations', ext:'.json', desc:'PCI-DSS, HIPAA, SOC2, NIST — ComplianceRule nodes, E_governs edges'},
              ].map(item=>(
                <div key={item.type} style={{ background:'#161b22', border:'1px solid #30363d', borderRadius:8, padding:16 }}>
                  <div style={{ fontWeight:600, color:'#c9d1d9', fontSize:13, marginBottom:4 }}>{item.label}</div>
                  <div style={{ fontSize:11, color:'#8b949e', marginBottom:12 }}>{item.desc}</div>
                  <label style={{ display:'inline-block', padding:'6px 14px', background:'#1f6feb', borderRadius:6, cursor:uploading?'not-allowed':'pointer', fontSize:12, color:'#fff', opacity:uploading?.6:1 }}>
                    {uploading?'Processing...': `Upload ${item.ext}`}
                    <input type="file" accept={item.ext==='.yaml'?'.yaml,.yml':item.ext} style={{display:'none'}} onChange={e=>handleUpload(e,item.type)} disabled={uploading} />
                  </label>
                </div>
              ))}
            </div>

            <div style={{ marginTop:24, borderTop:'1px solid #21262d', paddingTop:20, maxWidth:660 }}>
              <div style={{ fontSize:14, fontWeight:600, color:'#c9d1d9', marginBottom:6 }}>Pass 2 + Pass 3 — Linking</div>
              <div style={{ fontSize:12, color:'#8b949e', marginBottom:12 }}>Connect nodes across files and compute firewall posture on every resource node.</div>
              <button onClick={async()=>{ const r=await fetch(`${API}/api/v1/graph/link`,{method:'POST'}); setUploadResult(await r.json()); await fetchAll() }}
                style={{ padding:'8px 20px', background:'#388bfd', border:'none', borderRadius:6, color:'#fff', cursor:'pointer', fontSize:13, fontWeight:600 }}>
                Run Linking + Firewall Posture
              </button>
            </div>

            <div style={{ marginTop:24, borderTop:'1px solid #21262d', paddingTop:20, maxWidth:660 }}>
              <div style={{ fontSize:14, fontWeight:600, color:'#c9d1d9', marginBottom:6 }}>Ingest Finding (Track 2)</div>
              <div style={{ fontSize:12, color:'#8b949e', marginBottom:10 }}>Paste a single finding as JSON.</div>
              <textarea value={singleFinding} onChange={e=>setSingleFinding(e.target.value)}
                placeholder={'{\n  "tool_name": "semgrep",\n  "title": "SQL Injection",\n  "asset_location": "src/checkout.py",\n  "line": 42,\n  "severity": "high"\n}'}
                style={{ width:'100%', height:130, background:'#0d1117', border:'1px solid #30363d', borderRadius:6, color:'#c9d1d9', fontSize:12, padding:10, fontFamily:'monospace', resize:'vertical', boxSizing:'border-box' }} />
              <button onClick={handleIngestFinding} style={{ marginTop:8, padding:'7px 18px', background:'#238636', border:'none', borderRadius:6, color:'#fff', cursor:'pointer', fontSize:13, fontWeight:600 }}>
                Normalise + Ingest Finding
              </button>
            </div>

            {uploadResult && (
              <div style={{ marginTop:16, padding:14, borderRadius:8, maxWidth:660, background:uploadResult.error?'#2d1117':'#0d2818', border:`1px solid ${uploadResult.error?'#6e2020':'#1a4731'}` }}>
                {uploadResult.error
                  ? <div style={{color:'#f85149'}}>Error: {uploadResult.error}</div>
                  : <div>
                      <div style={{color:'#3fb950', fontWeight:600, marginBottom:6}}>✓ {uploadResult.message||uploadResult.status}</div>
                      {uploadResult.nodes_created!=null && <div style={{fontSize:12,color:'#8b949e'}}>Nodes: {uploadResult.nodes_created} · Edges: {uploadResult.edges_created}</div>}
                      {uploadResult.canonical_id && <div style={{fontSize:12,color:'#8b949e'}}>Canonical: {uploadResult.canonical_id} · Confidence: {uploadResult.confidence?.toFixed(2)}</div>}
                      {uploadResult.identifier_links!=null && <div style={{fontSize:12,color:'#8b949e'}}>ARN links: {uploadResult.identifier_links} · Cross-asset links: {uploadResult.cross_asset_links} · Firewall posture: {uploadResult.firewall_posture_computed} nodes</div>}
                      {uploadResult.human_review_required && <div style={{fontSize:12,color:'#d29922',marginTop:4}}>⚠ Below confidence threshold — queued for review</div>}
                    </div>
                }
              </div>
            )}
          </div>
        )}

        {/* Findings view */}
        {view==='findings' && (
          <div style={{ flex:1, padding:32, overflowY:'auto' }}>
            <div style={{ fontSize:18, fontWeight:700, color:'#f0f6fc', marginBottom:4 }}>Normalised Finding Pool</div>
            <div style={{ fontSize:13, color:'#8b949e', marginBottom:20 }}>Track 2 output. Every finding normalised to canonical CWE ID.</div>
            {findingStats && (
              <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:10, marginBottom:24, maxWidth:620 }}>
                {[
                  {label:'Total',        value:findingStats.total||0,         color:'#58a6ff'},
                  {label:'Need Review',  value:findingStats.needs_review||0,  color:'#f85149'},
                  {label:'Deterministic',value:findingStats.deterministic||0, color:'#3fb950'},
                  {label:'LLM Inferred', value:findingStats.llm_inferred||0,  color:'#d29922'},
                ].map(item=>(
                  <div key={item.label} style={{background:'#161b22', border:'1px solid #30363d', borderRadius:8, padding:16}}>
                    <div style={{fontSize:22, fontWeight:700, color:item.color}}>{item.value}</div>
                    <div style={{fontSize:11, color:'#8b949e'}}>{item.label}</div>
                  </div>
                ))}
              </div>
            )}
            {findings.length===0
              ? <div style={{color:'#8b949e', fontSize:13}}>No findings yet. Go to Ingest Asset to add findings.</div>
              : findings.map((f,i)=>(
                  <div key={i} style={{background:'#161b22', border:'1px solid #30363d', borderRadius:8, padding:14, marginBottom:8, maxWidth:800}}>
                    <div style={{display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:6}}>
                      <div>
                        <span style={{fontWeight:700, color:'#f0f6fc', fontSize:14}}>{f.canonical_id||'UNMAPPED'}</span>
                        <span style={{marginLeft:10, fontSize:11, color:'#8b949e'}}>{f.raw_term}</span>
                      </div>
                      <div style={{display:'flex', gap:8, alignItems:'center', flexShrink:0}}>
                        {f.human_review_required && <span style={{fontSize:10, padding:'2px 7px', background:'#f8514922', color:'#f85149', borderRadius:4, fontWeight:600}}>REVIEW</span>}
                        <span style={{fontSize:11, fontWeight:600, color: f.confidence>=0.9?'#3fb950':f.confidence>=0.7?'#d29922':'#f85149'}}>
                          {((f.confidence||0)*100).toFixed(0)}%
                        </span>
                      </div>
                    </div>
                    <div style={{display:'flex', gap:14, fontSize:11, color:'#8b949e', flexWrap:'wrap'}}>
                      <span>Tool: {f.tool_name}</span>
                      <span>Type: {f.source_type}</span>
                      <span>Location: {f.asset_location}</span>
                      <span>Method: {f.resolution_method}</span>
                    </div>
                    {f.description && <div style={{marginTop:6, fontSize:11, color:'#8b949e', lineHeight:1.5}}>{f.description.slice(0,200)}</div>}
                  </div>
                ))
            }
          </div>
        )}


        {/* Graph Link Review Interface — spec Section 4.4b */}
        {view==='review' && (
          <div style={{ flex:1, padding:32, overflowY:'auto' }}>
            <div style={{ fontSize:18, fontWeight:700, color:'#f0f6fc', marginBottom:4 }}>Graph Link Review Interface</div>
            <div style={{ fontSize:13, color:'#8b949e', marginBottom:20 }}>
              Edges created by fuzzy or LLM matching that need human confirmation.
              Each decision is permanent and written to the Component 8 registry.
            </div>

            {/* Stats row */}
            {reviewStats && (
              <div style={{ display:'flex', gap:12, marginBottom:24 }}>
                {[
                  {label:'Pending Review', value:reviewStats.pending||0, color:'#d29922'},
                  {label:'Confirmed',      value:reviewStats.confirmed||0, color:'#3fb950'},
                  {label:'Gaps Flagged',   value:reviewStats.gaps||0,    color:'#8b949e'},
                ].map(item=>(
                  <div key={item.label} style={{background:'#161b22', border:'1px solid #30363d', borderRadius:8, padding:'14px 20px'}}>
                    <div style={{fontSize:22, fontWeight:700, color:item.color}}>{item.value}</div>
                    <div style={{fontSize:11, color:'#8b949e'}}>{item.label}</div>
                  </div>
                ))}
              </div>
            )}

            {reviewItems.length === 0 ? (
              <div style={{color:'#3fb950', fontSize:14, padding:20, background:'#0d2818', borderRadius:8, border:'1px solid #1a4731'}}>
                ✓ No links pending review. All edges are deterministic or human-confirmed.
              </div>
            ) : (
              <div style={{maxWidth:900}}>
                {reviewItems.map((item, i) => (
                  <div key={item.edge_id} style={{
                    background:'#161b22', border:'1px solid #30363d', borderRadius:8,
                    padding:20, marginBottom:16,
                    opacity: reviewDeciding === item.edge_id ? 0.5 : 1
                  }}>
                    {/* Header */}
                    <div style={{display:'flex', justifyContent:'space-between', marginBottom:14}}>
                      <div style={{display:'flex', alignItems:'center', gap:10}}>
                        <span style={{fontSize:11, padding:'2px 8px', background:'#d2992222', color:'#d29922', borderRadius:4, fontWeight:600}}>
                          {item.method}
                        </span>
                        <span style={{fontSize:11, color:'#8b949e'}}>
                          confidence: {((item.confidence||0)*100).toFixed(0)}%
                        </span>
                        <span style={{fontSize:11, padding:'2px 8px', background:'#388bfd22', color:'#388bfd', borderRadius:4}}>
                          {item.edge_type}
                        </span>
                      </div>
                      <span style={{fontSize:11, color:'#8b949e'}}>{i+1} of {reviewItems.length}</span>
                    </div>

                    {/* Two nodes side by side */}
                    <div style={{display:'grid', gridTemplateColumns:'1fr auto 1fr', gap:12, alignItems:'center', marginBottom:16}}>
                      {/* From node */}
                      <div style={{background:'#0d1117', borderRadius:6, padding:12, border:'1px solid #21262d'}}>
                        <div style={{fontSize:11, color:'#8b949e', marginBottom:4}}>FROM</div>
                        <div style={{fontWeight:700, color:'#f0f6fc', fontSize:14, marginBottom:4}}>{item.from.name}</div>
                        <div style={{fontSize:11, color:'#8b949e', marginBottom:2}}>
                          {item.from.domain} · {item.from.type}
                        </div>
                        {item.from.file && <div style={{fontSize:10, color:'#555', wordBreak:'break-all'}}>{item.from.file}</div>}
                        {item.from.summary && (
                          <div style={{marginTop:6, fontSize:11, color:'#8b949e', lineHeight:1.4}}>{item.from.summary}</div>
                        )}
                      </div>

                      {/* Arrow */}
                      <div style={{textAlign:'center', color:'#388bfd', fontSize:18}}>→</div>

                      {/* To node */}
                      <div style={{background:'#0d1117', borderRadius:6, padding:12, border:'1px solid #21262d'}}>
                        <div style={{fontSize:11, color:'#8b949e', marginBottom:4}}>TO</div>
                        <div style={{fontWeight:700, color:'#f0f6fc', fontSize:14, marginBottom:4}}>{item.to.name}</div>
                        <div style={{fontSize:11, color:'#8b949e', marginBottom:2}}>
                          {item.to.domain} · {item.to.type}
                        </div>
                        {item.to.file && <div style={{fontSize:10, color:'#555', wordBreak:'break-all'}}>{item.to.file}</div>}
                        {item.to.summary && (
                          <div style={{marginTop:6, fontSize:11, color:'#8b949e', lineHeight:1.4}}>{item.to.summary}</div>
                        )}
                      </div>
                    </div>

                    {/* Decision buttons */}
                    <div style={{display:'flex', gap:10}}>
                      {[
                        {decision:'confirmed', label:'✓ Same service', color:'#238636', bg:'#0d2818', border:'#1a4731'},
                        {decision:'rejected',  label:'✗ Not the same', color:'#f85149', bg:'#2d1117', border:'#6e2020'},
                        {decision:'unsure',    label:'? Not sure — flag gap', color:'#8b949e', bg:'#161b22', border:'#30363d'},
                      ].map(btn => (
                        <button key={btn.decision}
                          disabled={reviewDeciding !== null}
                          onClick={async () => {
                            setReviewDeciding(item.edge_id)
                            try {
                              await fetch(`${API}/api/v1/review/decide`, {
                                method: 'POST',
                                headers: {'Content-Type':'application/json'},
                                body: JSON.stringify({edge_id: item.edge_id, decision: btn.decision})
                              })
                              await fetchAll()
                            } finally { setReviewDeciding(null) }
                          }}
                          style={{
                            padding:'8px 16px', border:`1px solid ${btn.border}`,
                            borderRadius:6, background:btn.bg, color:btn.color,
                            cursor: reviewDeciding ? 'not-allowed' : 'pointer',
                            fontSize:13, fontWeight:600,
                            opacity: reviewDeciding ? 0.5 : 1,
                          }}>
                          {btn.label}
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Stats view */}
        {view==='stats' && (
          <div style={{ flex:1, padding:32, overflowY:'auto' }}>
            <div style={{ fontSize:18, fontWeight:700, color:'#f0f6fc', marginBottom:20 }}>Stats</div>
            <div style={{display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:12, maxWidth:460, marginBottom:24}}>
              {[{label:'KG Nodes',value:stats?.total_nodes||0},{label:'KG Edges',value:stats?.total_edges||0},{label:'Findings',value:findingStats?.total||0}].map(item=>(
                <div key={item.label} style={{background:'#161b22', border:'1px solid #30363d', borderRadius:8, padding:20}}>
                  <div style={{fontSize:28, fontWeight:700, color:'#58a6ff'}}>{item.value}</div>
                  <div style={{fontSize:12, color:'#8b949e', marginTop:4}}>{item.label}</div>
                </div>
              ))}
            </div>
            {Object.entries(stats?.nodes_by_domain||{}).map(([d,c]:any)=>(
              <div key={d} style={{display:'flex', justifyContent:'space-between', padding:'8px 12px', background:'#161b22', border:'1px solid #30363d', borderRadius:6, marginBottom:6, maxWidth:360}}>
                <span style={{color:DOMAIN_COLORS[d]||'#888'}}>● {d}</span>
                <span style={{color:'#f0f6fc', fontWeight:600}}>{c}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
