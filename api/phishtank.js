module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  if (req.method === 'OPTIONS') return res.status(200).end()
  const url = req.query.url || (req.body && req.body.url)
  if (!url) return res.status(400).json({ error: 'missing url' })
  try {
    const body = new URLSearchParams({ url, format: 'json' }).toString()
    const r = await fetch('https://checkurl.phishtank.com/checkurl/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'SafeCheck/1.0' },
      body
    })
    let data
    try { data = await r.json() } catch { data = { unavailable: true } }
    let phishing = null
    let verified = null
    let first_report = null
    let last_update = null
    if (data && data.results) {
      const d = data.results
      phishing = !!d.in_database && !!d.valid
      verified = !!d.verified
      first_report = d.first_seen || null
      last_update = d.last_update || null
    }
    res.status(200).json({ phishing, verified, first_report, last_update, raw: data })
  } catch (e) {
    res.status(200).json({ phishing: null, verified: null, first_report: null, last_update: null, raw: 'unavailable' })
  }
}