module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  if (req.method === 'OPTIONS') return res.status(200).end()
  const url = req.query.url || (req.body && req.body.url)
  if (!url) return res.status(400).json({ error: 'missing url' })
  const key = process.env.IPQS_KEY
  if (!key) return res.status(500).json({ error: 'missing IPQS_KEY' })
  try {
    const r = await fetch(`https://ipqualityscore.com/api/json/url/${key}/${encodeURIComponent(url)}`)
    const d = await r.json()
    const out = {
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
    res.status(200).json(out)
  } catch (e) {
    res.status(200).json({ risk_score: null, phishing: null, malware: null, suspicious: null, unsafe: null, proxy: null, vpn: null, tor: null, bots: null, domain_age: null, raw: 'unavailable' })
  }
}