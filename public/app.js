const homeView = document.getElementById('view-home')
const loadingView = document.getElementById('view-loading')
const resultView = document.getElementById('view-result')
const analyzeBtn = document.getElementById('analyze-btn')
const reanalyzeBtn = document.getElementById('reanalyze-btn')
const urlInput = document.getElementById('url-input')
const loadingUrl = document.getElementById('loading-url')
const verdictBox = document.getElementById('verdict-box')
const verdictTitle = document.getElementById('verdict-title')
const scoreEl = document.getElementById('score')
const explanationEl = document.getElementById('explanation')
const tabContent = document.getElementById('tab-content')
const tabs = Array.from(document.querySelectorAll('.tab'))
const serviceStatusEl = document.getElementById('service-status')
const toggleDiagnosticsBtn = document.getElementById('toggle-diagnostics')
let diagnosticsOpen = false

function show(view) {
  homeView.classList.add('hidden')
  loadingView.classList.add('hidden')
  resultView.classList.add('hidden')
  view.classList.remove('hidden')
}

function truncateUrl(u) {
  if (!u) return ''
  return u.length > 64 ? u.slice(0, 61) + '…' : u
}

function setVerdict(verdict, score, explanation) {
  verdictBox.classList.remove('result-safe','result-suspicious','result-dangerous')
  if (verdict === 'safe') verdictBox.classList.add('result-safe')
  if (verdict === 'suspicious') verdictBox.classList.add('result-suspicious')
  if (verdict === 'dangerous') verdictBox.classList.add('result-dangerous')
  verdictTitle.textContent = verdict === 'safe' ? 'Este sitio es seguro' : verdict === 'suspicious' ? 'Sitio sospechoso' : 'Sitio peligroso (phishing)'
  scoreEl.textContent = `${score}/10`
  explanationEl.textContent = explanation || ''
}

function renderKV(k, v) {
  const row = document.createElement('div')
  row.className = 'kv'
  const key = document.createElement('div')
  key.textContent = k
  const val = document.createElement('div')
  let text = v
  if (Array.isArray(v)) text = v.join(', ')
  else if (typeof v === 'object' && v !== null) text = ''
  val.textContent = String(text)
  row.appendChild(key)
  row.appendChild(val)
  return row
}

function renderTab(name, data) {
  tabContent.innerHTML = ''
  const title = document.createElement('div')
  const badge = document.createElement('span')
  badge.className = 'badge ' + (name === 'virustotal' ? (data.malicious_count > 0 ? 'dangerous' : data.suspicious_count > 0 ? 'suspicious' : 'safe') : name === 'ipqs' ? (data.unsafe || data.phishing ? 'dangerous' : data.suspicious ? 'suspicious' : 'safe') : name === 'abuse' ? (data.blacklisted ? 'dangerous' : 'safe') : 'safe')
  badge.textContent = name.toUpperCase()
  title.appendChild(badge)
  tabContent.appendChild(title)
  const pairs = buildPairs(name, data || {})
  pairs.forEach(p => tabContent.appendChild(renderKV(p.k, p.v)))
}

function renderStatus(status) {
  serviceStatusEl.innerHTML = ''
  const backendRow = document.createElement('div')
  backendRow.className = 'row'
  const k1 = document.createElement('div')
  k1.textContent = 'Backend'
  const v1 = document.createElement('div')
  const b1 = document.createElement('span')
  b1.className = 'badge ' + (API_BASE ? 'ok' : 'err')
  b1.textContent = API_BASE || 'local (sin API)'
  v1.appendChild(b1)
  backendRow.appendChild(k1)
  backendRow.appendChild(v1)
  serviceStatusEl.appendChild(backendRow)

  const map = {
    ipqs: 'IPQualityScore',
    virustotal: 'VirusTotal',
    abuse: 'AbuseIPDB/URLHaus'
  }
  Object.entries(map).forEach(([key,label]) => {
    const row = document.createElement('div')
    row.className = 'row'
    const k = document.createElement('div')
    k.textContent = label
    const v = document.createElement('div')
    const s = status && status[key]
    const b = document.createElement('span')
    b.className = 'badge ' + (s === 'missing_key' ? 'missing' : s === 'error' ? 'err' : 'ok')
    b.textContent = s === 'missing_key' ? 'Sin clave' : s === 'error' ? 'Error' : 'OK'
    v.appendChild(b)
    row.appendChild(k)
    row.appendChild(v)
    serviceStatusEl.appendChild(row)
  })
  if (!diagnosticsOpen) serviceStatusEl.style.display = 'none'
}

const API_BASE = (() => {
  try {
    const sp = new URLSearchParams(typeof location !== 'undefined' ? location.search : '')
    const q = sp.get('api')
    let base = q || (typeof window !== 'undefined' && window.SAFECHECK_API_BASE ? window.SAFECHECK_API_BASE : '')
    if (base) base = base.trim().replace(/^['"`]+|['"`]+$/g, '')
    if (!base) return ''
    const u = new URL(base)
    return u.origin.replace(/\/$/, '')
  } catch { return '' }
})()
const DEFAULT_FALLBACK_API = 'https://safecheck-kohl.vercel.app'

async function analyze(url) {
  show(loadingView)
  loadingUrl.textContent = truncateUrl(url)
  analyzeBtn.disabled = true
  try {
    let apiBase = API_BASE || ((typeof location !== 'undefined' && /^https?/.test(location.protocol)) ? location.origin : '')
    if (!apiBase) apiBase = DEFAULT_FALLBACK_API
    let reqUrl = `${apiBase}/api/combined?url=${encodeURIComponent(url)}`
    let res = await fetch(reqUrl)
    let json = null
    const ct = res.headers.get('content-type') || ''
    if (ct.includes('application/json')) {
      try { json = await res.json() } catch {}
    } else {
      const text = await res.text()
      if (apiBase !== DEFAULT_FALLBACK_API) {
        apiBase = DEFAULT_FALLBACK_API
        reqUrl = `${apiBase}/api/combined?url=${encodeURIComponent(url)}`
        res = await fetch(reqUrl)
        const ct2 = res.headers.get('content-type') || ''
        if (ct2.includes('application/json')) {
          try { json = await res.json() } catch {}
        }
      }
      if (!json) throw new Error(`non_json:${res.status}:${res.statusText}:${reqUrl}`)
    }
    if (!json) throw new Error('bad_json')
    setVerdict(json.globalVerdict, json.score, json.explanation)
    renderStatus(json.serviceStatus || {})
    tabs.forEach(t => t.classList.remove('active'))
    tabs[0].classList.add('active')
    renderTab('ipqs', json.services.ipqs)
    tabs.forEach(t => {
      t.onclick = () => {
        tabs.forEach(tt=>tt.classList.remove('active'))
        t.classList.add('active')
        const key = t.getAttribute('data-tab')
        renderTab(key, json.services[key])
      }
    })
    diagnosticsOpen = false
    serviceStatusEl.style.display = 'none'
    if (toggleDiagnosticsBtn) toggleDiagnosticsBtn.textContent = 'Ver detalles'
    show(resultView)
  } catch (e) {
    const emsg = String(e && e.message || '')
    const isNonJson = emsg.startsWith('non_json')
    const hint = isNonJson ? 'Backend no disponible o ruta /api inexistente' : 'Error consultando el backend'
    const used = emsg.split(':').slice(-1)[0] || (API_BASE ? `${API_BASE}/api/combined` : `${DEFAULT_FALLBACK_API}/api/combined`)
    setVerdict('suspicious', 5, `${hint} · Usado: ${used} · Usa ?api=https://safecheck-kohl.vercel.app`)
    tabContent.innerHTML = ''
    show(resultView)
  } finally {
    analyzeBtn.disabled = false
  }
}

analyzeBtn.addEventListener('click', () => {
  const u = urlInput.value.trim()
  if (!u) return
  try { new URL(u) } catch { return }
  analyze(u)
})

reanalyzeBtn.addEventListener('click', () => {
  urlInput.focus()
  show(homeView)
})

if (toggleDiagnosticsBtn) {
  toggleDiagnosticsBtn.addEventListener('click', () => {
    diagnosticsOpen = !diagnosticsOpen
    serviceStatusEl.style.display = diagnosticsOpen ? 'block' : 'none'
    toggleDiagnosticsBtn.textContent = diagnosticsOpen ? 'Ocultar detalles' : 'Ver detalles'
  })
}

function yn(b) { return b === true ? 'Sí' : b === false ? null : null }
function fmtDate(s) {
  if (!s) return null
  const d = new Date(s)
  if (isNaN(d.getTime())) return null
  return d.toLocaleString('es-ES')
}
function nonEmpty(v) {
  if (v === null || v === undefined) return false
  if (typeof v === 'string') return v.trim().length > 0
  if (Array.isArray(v)) return v.length > 0
  if (typeof v === 'number') return true
  if (typeof v === 'boolean') return v === true
  return true
}
function cleanStr(s) {
  if (typeof s !== 'string') return s
  return s.replace(/^['"`]+|['"`]+$/g, '')
}
function buildPairs(name, data) {
  const out = []
  const push = (k, v) => { if (nonEmpty(v)) out.push({ k, v }) }
  if (name === 'phishtank') {
    if (data.raw === 'unavailable') push('Estado', 'Servicio temporalmente no disponible')
    const ph = yn(data.phishing)
    const ver = yn(data.verified)
    if (ph) push('Phishing conocido', ph)
    if (ver) push('Verificado', ver)
    const fr = fmtDate(data.first_report)
    const lu = fmtDate(data.last_update)
    if (fr) push('Primera detección', fr)
    if (lu) push('Última actualización', lu)
    if (out.length === 0) push('Resumen', 'Sin coincidencias conocidas')
    return out
  }
  if (name === 'ipqs') {
    if (typeof data.risk_score === 'number') push('Riesgo', `${data.risk_score}/100`)
    const flags = []
    if (data.phishing) flags.push('Phishing')
    if (data.malware) flags.push('Malware')
    if (data.suspicious) flags.push('Sospechoso')
    if (data.unsafe) flags.push('Inseguro')
    if (data.proxy) flags.push('Proxy')
    if (data.vpn) flags.push('VPN')
    if (data.tor) flags.push('Tor')
    if (data.bots) flags.push('Bots')
    push('Advertencias', flags.length ? flags.join(', ') : 'Sin hallazgos')
    const age = data.domain_age && (data.domain_age.human || null)
    if (age) push('Edad de dominio', age)
    const raw = data.raw || {}
    if (nonEmpty(raw.country_code)) push('País', raw.country_code)
    if (nonEmpty(raw.server)) push('Servidor', raw.server)
    if (nonEmpty(raw.status_code)) push('HTTP', String(raw.status_code))
    if (nonEmpty(raw.content_type)) push('Contenido', raw.content_type)
    if (nonEmpty(raw.domain_rank)) push('Ranking de dominio', String(raw.domain_rank))
    if (nonEmpty(raw.page_size)) push('Tamaño de página', `${Math.round(raw.page_size/1024)} KB`)
    if (raw.spf_record) push('SPF', 'Sí')
    if (raw.dmarc_record) push('DMARC', 'Sí')
    if (raw.redirected) push('Redirección', 'Sí')
    if (raw.risky_tld) push('TLD riesgoso', 'Sí')
    if (Array.isArray(raw.technologies) && raw.technologies.length) push('Tecnologías', raw.technologies.slice(0,6).join(', '))
    const fu = cleanStr(raw.final_url)
    if (nonEmpty(fu)) push('URL final', fu)
    return out
  }
  if (name === 'virustotal') {
    const cls = data.classification === 'malicious' ? 'Peligroso' : data.classification === 'suspicious' ? 'Sospechoso' : data.classification === 'harmless' ? 'Limpio' : null
    if (cls) push('Clasificación', cls)
    if (typeof data.malicious_count === 'number') push('Detecciones maliciosas', String(data.malicious_count))
    if (typeof data.suspicious_count === 'number') push('Detecciones sospechosas', String(data.suspicious_count))
    if (typeof data.harmless_count === 'number') push('Detecciones limpias', String(data.harmless_count))
    if (typeof data.undetected_count === 'number') push('No detectado', String(data.undetected_count))
    const engines = Array.isArray(data.engines) ? data.engines : []
    push('Motores detectores', engines.length ? engines.slice(0, 8).join(', ') : 'Ninguno')
    if (data.analysis_id) push('ID análisis', data.analysis_id)
    return out
  }
  if (name === 'abuse') {
    if (nonEmpty(data.ip)) push('IP', data.ip)
    const a = data.abuseIPDB || {}
    if (a && a.totalReports > 0) push('Reportes de abuso', String(a.totalReports))
    const lr = a && a.lastReportedAt ? fmtDate(a.lastReportedAt) : null
    if (lr) push('Último reporte', lr)
    const isp = a && a.raw && a.raw.data && a.raw.data.isp ? a.raw.data.isp : null
    if (isp) push('Proveedor', isp)
    const cc = a && a.raw && a.raw.data && a.raw.data.countryCode ? a.raw.data.countryCode : null
    if (cc) push('País IP', cc)
    const ut = a && a.raw && a.raw.data && a.raw.data.usageType ? a.raw.data.usageType : null
    if (ut) push('Uso', ut)
    const isTor = a && a.raw && a.raw.data && a.raw.data.isTor
    if (isTor) push('Tor', 'Sí')
    const hostnames = a && a.raw && a.raw.data && Array.isArray(a.raw.data.hostnames) ? a.raw.data.hostnames.slice(0, 4) : []
    if (hostnames.length) push('Hostnames', hostnames.join(', '))
    if (data.blacklisted) push('Listas negras', 'Sí')
    const uh = data.urlhaus || {}
    if (uh.listed) push('URLHaus', 'Listado')
    if (uh.threat) push('Amenaza', uh.threat)
    if (uh.url_status) push('Estado URL', uh.url_status)
    if (out.length === 0) push('Resumen', 'Sin reportes y sin listas negras')
    return out
  }
  return out
}

show(homeView)
