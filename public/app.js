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
  val.textContent = typeof v === 'object' ? JSON.stringify(v) : String(v)
  row.appendChild(key)
  row.appendChild(val)
  return row
}

function renderTab(name, data) {
  tabContent.innerHTML = ''
  const title = document.createElement('div')
  const badge = document.createElement('span')
  badge.className = 'badge ' + (name === 'phishtank' ? (data.phishing ? 'dangerous' : 'safe') : name === 'virustotal' ? (data.malicious_count > 0 ? 'dangerous' : data.suspicious_count > 0 ? 'suspicious' : 'safe') : name === 'ipqs' ? (data.unsafe || data.phishing ? 'dangerous' : data.suspicious ? 'suspicious' : 'safe') : (data.blacklisted ? 'dangerous' : 'safe'))
  badge.textContent = name.toUpperCase()
  title.appendChild(badge)
  tabContent.appendChild(title)
  Object.entries(data || {}).forEach(([k,v])=>tabContent.appendChild(renderKV(k,v)))
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
    phishtank: 'PhishTank',
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
    renderTab('phishtank', json.services.phishtank)
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

show(homeView)