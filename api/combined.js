module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  if (req.method === 'OPTIONS') return res.status(200).end()
  const input = req.query.url || (req.body && req.body.url)
  if (!input) return res.status(400).json({ error: 'missing url' })
  try {

    const ipqsKey = process.env.IPQS_KEY
    const ipqsRes = await (async () => {
      if (!ipqsKey) return { missingKey: true }
      try {
        const r = await fetch(`https://ipqualityscore.com/api/json/url/${ipqsKey}/${encodeURIComponent(input)}`)
        const d = await r.json()
        return {
          risk_score: d.risk_score,
          phishing: !!d.phishing,
          malware: !!d.malware,
          suspicious: !!d.suspicious,
          unsafe: !!d.unsafe,
          proxy: !!d.proxy,
          vpn: !!d.vpn,
          tor: !!d.tor,
          bots: !!d.bot,
          domain_age: d.domain_age || null,
          raw: d
        }
      } catch { return { error: true } }
    })()

    const vtKey = process.env.VT_KEY
    const vtRes = await (async () => {
      if (!vtKey) return { missingKey: true }
      try {
        const body = new URLSearchParams({ url: input }).toString()
        const post = await fetch('https://www.virustotal.com/api/v3/urls', { method: 'POST', headers: { 'x-apikey': vtKey, 'Content-Type': 'application/x-www-form-urlencoded' }, body })
        const pj = await post.json()
        const id = pj.data && pj.data.id
        if (!id) return { malicious_count: 0, suspicious_count: 0, harmless_count: 0, undetected_count: 0, engines: [], classification: 'unknown', raw: pj }
        const ar = await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, { headers: { 'x-apikey': vtKey } })
        const aj = await ar.json()
        const stats = aj.data && aj.data.attributes && aj.data.attributes.stats ? aj.data.attributes.stats : {}
        const results = aj.data && aj.data.attributes && aj.data.attributes.results ? aj.data.attributes.results : {}
        const engines = Object.entries(results).filter(([_, v]) => v.category === 'malicious' || v.category === 'suspicious').map(([k, _]) => k)
        let classification = 'harmless'
        if ((stats.malicious || 0) > 0) classification = 'malicious'
        else if ((stats.suspicious || 0) > 0) classification = 'suspicious'
        return { malicious_count: stats.malicious || 0, suspicious_count: stats.suspicious || 0, harmless_count: stats.harmless || 0, undetected_count: stats.undetected || 0, engines, classification, raw: aj }
      } catch { return { error: true } }
    })()

    const abuseKey = process.env.ABUSE_KEY
    const abRes = await (async () => {
      try {
        const u = new URL(input)
        const dns = require('dns').promises
        let ip = null
        try { const l = await dns.lookup(u.hostname); ip = l.address } catch {}
        let abuseIPDB = null
        if (ip && abuseKey) {
          try {
            const r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, { headers: { 'Key': abuseKey, 'Accept': 'application/json' } })
            const d = await r.json()
            abuseIPDB = {
              score: d.data ? d.data.abuseConfidenceScore : null,
              totalReports: d.data ? d.data.totalReports : null,
              lastReportedAt: d.data ? d.data.lastReportedAt : null,
              blacklisted: d.data ? (d.data.abuseConfidenceScore || 0) > 0 : null,
              raw: d
            }
          } catch { abuseIPDB = null }
        }
        const body = new URLSearchParams({ url: input }).toString()
        let urlhaus = null
        try {
          const hr = await fetch('https://urlhaus-api.abuse.ch/v1/url/', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body })
          const hd = await hr.json()
          urlhaus = {
            listed: hd.query_status === 'ok',
            url_status: hd.url_status || null,
            threat: hd.threat || null,
            date_added: hd.date_added || null,
            reporter: hd.reporter || null,
            raw: hd
          }
        } catch { urlhaus = null }
        return { ip, abuseIPDB, urlhaus, blacklisted: (abuseIPDB && abuseIPDB.blacklisted) || (urlhaus && urlhaus.listed) || false, missingKey: !abuseKey }
      } catch { return { ip: null, abuseIPDB: null, urlhaus: null, blacklisted: null, missingKey: !abuseKey } }
    })()

    let verdict = 'safe'
    const strong = (
      (ipqsRes && (ipqsRes.unsafe || ipqsRes.phishing)) ||
      (vtRes && (vtRes.malicious_count || 0) > 0) ||
      (abRes && (abRes.blacklisted === true))
    )
    const warn = (
      (ipqsRes && (ipqsRes.suspicious || (ipqsRes.risk_score || 0) >= 50)) ||
      (vtRes && (vtRes.suspicious_count || 0) > 0) ||
      (abRes && ((abRes.abuseIPDB && (abRes.abuseIPDB.totalReports || 0) > 0) || abRes.urlhaus && abRes.urlhaus.url_status === 'online'))
    )
    if (strong) verdict = 'dangerous'
    else if (warn) verdict = 'suspicious'
    let score = 10
    if (ipqsRes && typeof ipqsRes.risk_score === 'number') score -= Math.round(ipqsRes.risk_score / 12)
    if (ipqsRes && ipqsRes.unsafe) score -= 7
    if (ipqsRes && ipqsRes.phishing) score -= 7
    if (ipqsRes && ipqsRes.malware) score -= 5
    if (ipqsRes && ipqsRes.suspicious) score -= 3
    if (ipqsRes && (ipqsRes.proxy || ipqsRes.vpn || ipqsRes.tor)) score -= 2
    if (vtRes && (vtRes.malicious_count || 0) > 0) score -= 8
    else if (vtRes && (vtRes.suspicious_count || 0) > 0) score -= 3
    if (abRes && abRes.abuseIPDB && typeof abRes.abuseIPDB.score === 'number') score -= Math.round(abRes.abuseIPDB.score / 15)
    if (abRes && abRes.blacklisted) score -= 4
    
    if (score < 0) score = 0
    if (score > 10) score = 10
    const missingKeys = [ipqsRes, vtRes, abRes].some(s => s && s.missingKey)
    const serviceStatus = {
      ipqs: ipqsRes && ipqsRes.missingKey ? 'missing_key' : (ipqsRes && ipqsRes.error ? 'error' : 'ok'),
      virustotal: vtRes && vtRes.missingKey ? 'missing_key' : (vtRes && vtRes.error ? 'error' : 'ok'),
      abuse: abRes && abRes.missingKey ? 'missing_key' : ((abRes && (abRes.urlhaus || abRes.abuseIPDB)) ? 'ok' : 'error')
    }
    const explanation = missingKeys
      ? 'Configura las API keys para resultados completos'
      : verdict === 'dangerous'
        ? 'Coincide con reportes de riesgo conocidos'
        : verdict === 'suspicious'
          ? 'Dominio con patrones inusuales o advertencias'
          : 'Certificados, reputación y listas sin coincidencias'
    res.status(200).json({ globalVerdict: verdict, score, explanation, serviceStatus, services: { ipqs: ipqsRes || {}, virustotal: vtRes || {}, abuse: abRes || {} } })
  } catch (e) {
    res.status(200).json({ globalVerdict: 'suspicious', score: 5, explanation: 'No fue posible combinar todos los servicios', services: { phishtank: {}, ipqs: {}, virustotal: {}, abuse: {} } })
  }
}
