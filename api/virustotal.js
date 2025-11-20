module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  if (req.method === 'OPTIONS') return res.status(200).end()
  const url = req.query.url || (req.body && req.body.url)
  if (!url) return res.status(400).json({ error: 'missing url' })
  const key = process.env.VT_KEY
  if (!key) return res.status(500).json({ error: 'missing VT_KEY' })
  try {
    const body = new URLSearchParams({ url }).toString()
    const post = await fetch('https://www.virustotal.com/api/v3/urls', { method: 'POST', headers: { 'x-apikey': key, 'Content-Type': 'application/x-www-form-urlencoded' }, body })
    const pj = await post.json()
    const id = pj.data && pj.data.id
    if (!id) return res.status(200).json({ malicious_count: 0, suspicious_count: 0, harmless_count: 0, undetected_count: 0, engines: [], classification: 'unknown', raw: pj })
    const ar = await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, { headers: { 'x-apikey': key } })
    const aj = await ar.json()
    const stats = aj.data && aj.data.attributes && aj.data.attributes.stats ? aj.data.attributes.stats : {}
    const results = aj.data && aj.data.attributes && aj.data.attributes.results ? aj.data.attributes.results : {}
    const engines = Object.entries(results).filter(([_,v]) => v.category === 'malicious' || v.category === 'suspicious').map(([k,_]) => k)
    let classification = 'harmless'
    if ((stats.malicious || 0) > 0) classification = 'malicious'
    else if ((stats.suspicious || 0) > 0) classification = 'suspicious'
    res.status(200).json({ malicious_count: stats.malicious || 0, suspicious_count: stats.suspicious || 0, harmless_count: stats.harmless || 0, undetected_count: stats.undetected || 0, engines, classification, raw: aj })
  } catch (e) {
    res.status(200).json({ malicious_count: 0, suspicious_count: 0, harmless_count: 0, undetected_count: 0, engines: [], classification: 'unknown', raw: 'unavailable' })
  }
}