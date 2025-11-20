const dns = require('dns').promises

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  if (req.method === 'OPTIONS') return res.status(200).end()
  const input = req.query.url || (req.body && req.body.url)
  if (!input) return res.status(400).json({ error: 'missing url' })
  const key = process.env.ABUSE_KEY
  if (!key) return res.status(500).json({ error: 'missing ABUSE_KEY' })
  try {
    const u = new URL(input)
    let ip = null
    try { const l = await dns.lookup(u.hostname); ip = l.address } catch {}
    let abuseIPDB = null
    if (ip) {
      const r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, { headers: { 'Key': key, 'Accept': 'application/json' } })
      const d = await r.json()
      abuseIPDB = {
        score: d.data ? d.data.abuseConfidenceScore : null,
        totalReports: d.data ? d.data.totalReports : null,
        lastReportedAt: d.data ? d.data.lastReportedAt : null,
        blacklisted: d.data ? (d.data.abuseConfidenceScore || 0) > 0 : null,
        raw: d
      }
    }
    const body = new URLSearchParams({ url: input }).toString()
    const hr = await fetch('https://urlhaus-api.abuse.ch/v1/url/', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body })
    const hd = await hr.json()
    const urlhaus = {
      listed: hd.query_status === 'ok',
      url_status: hd.url_status || null,
      threat: hd.threat || null,
      date_added: hd.date_added || null,
      reporter: hd.reporter || null,
      raw: hd
    }
    res.status(200).json({ ip, abuseIPDB, urlhaus, blacklisted: (abuseIPDB && abuseIPDB.blacklisted) || urlhaus.listed })
  } catch (e) {
    res.status(200).json({ ip: null, abuseIPDB: null, urlhaus: null, blacklisted: null })
  }
}