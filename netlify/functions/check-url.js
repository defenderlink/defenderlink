\
const fetch = require('node-fetch');
const { combineScores } = require('../../utils/risk');
const { normalizeUrl, basicDns, headFollow, getWhois } = require('../../utils/helpers');

const GSB_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;
const VT_KEY  = process.env.VIRUSTOTAL_API_KEY;
const OPENPHISH_FEED = 'https://openphish.com/feed.txt';
const PHISHTANK_FEED = 'https://data.phishtank.com/data/online-valid.json';

let openPhishSet = null;
let openPhishETag = null;
let phishTank = null;
let phishTankETag = null;

async function ensureFeeds() {
  // OpenPhish
  try {
    const hdrs = openPhishETag ? {'If-None-Match': openPhishETag} : {};
    const res = await fetch(OPENPHISH_FEED, { headers: hdrs, timeout: 8000 });
    if (res.status === 200) {
      openPhishETag = res.headers.get('etag');
      const text = await res.text();
      openPhishSet = new Set(text.split('\n').map(x => x.trim()).filter(Boolean));
    }
  } catch {}
  // PhishTank
  try {
    const hdrs2 = phishTankETag ? {'If-None-Match': phishTankETag} : {};
    const res2 = await fetch(PHISHTANK_FEED, { headers: hdrs2, timeout: 8000 });
    if (res2.status === 200) {
      phishTankETag = res2.headers.get('etag');
      phishTank = await res2.json();
    }
  } catch {}
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }
  await ensureFeeds();

  let body = {};
  try { body = JSON.parse(event.body || '{}'); } catch {}
  const normalized = normalizeUrl(body.url || '');
  if (!normalized) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Invalid URL' }) };
  }
  const u = new URL(normalized);
  const domain = u.hostname;

  const parts = [];
  const details = { meta: { checkedAt: new Date().toISOString() } };

  // Google Safe Browsing
  if (GSB_KEY) {
    try {
      const gsbBody = {
        client: { clientId: 'defenderlink', clientVersion: '1.0' },
        threatInfo: {
          threatTypes: ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url: normalized }]
        }
      };
      const gsbRes = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GSB_KEY}`, {
        method: 'POST',
        headers: {'content-type':'application/json'},
        body: JSON.stringify(gsbBody)
      });
      const gsbJson = await gsbRes.json();
      const hit = !!gsbJson.matches;
      parts.push({ source: 'gsb', score: hit ? 100 : 0, reason: hit ? 'Listed by Google Safe Browsing' : 'Not listed' });
      details.google_safe_browsing = hit ? gsbJson : { status: 'not_listed' };
    } catch (e) {
      details.google_safe_browsing = { error: e.message };
      parts.push({ source: 'gsb', score: 0, reason: 'GSB check failed' });
    }
  } else {
    parts.push({ source: 'gsb', score: 0, reason: 'GSB key not set' });
    details.google_safe_browsing = { warning: 'GOOGLE_SAFE_BROWSING_KEY not set' };
  }

  // VirusTotal URL
  if (VT_KEY) {
    try {
      const submit = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: { 'x-apikey': VT_KEY, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ url: normalized })
      });
      const subJson = await submit.json();
      let vtScore = 0;
      let vtDetail = subJson;
      try {
        const analysisId = subJson.data && subJson.data.id;
        if (analysisId) {
          const anRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, { headers: { 'x-apikey': VT_KEY } });
          const anJson = await anRes.json();
          vtDetail = anJson;
          const stats = anJson.data && anJson.data.attributes && anJson.data.attributes.stats || {};
          const malicious = stats.malicious || 0;
          const suspicious = stats.suspicious || 0;
          vtScore = Math.min(100, (malicious * 20) + (suspicious * 10));
        }
      } catch {}
      parts.push({ source: 'vt', score: vtScore, reason: 'VirusTotal URL stats' });
      details.virustotal = vtDetail;
    } catch (e) {
      details.virustotal = { error: e.message };
      parts.push({ source: 'vt', score: 0, reason: 'VT check failed' });
    }
  } else {
    parts.push({ source: 'vt', score: 0, reason: 'VT key not set' });
    details.virustotal = { warning: 'VIRUSTOTAL_API_KEY not set' };
  }

  // OpenPhish & PhishTank
  try {
    const listedOpen = openPhishSet && (openPhishSet.has(normalized) || openPhishSet.has(u.origin));
    parts.push({ source: 'openphish', score: listedOpen ? 100 : 0, reason: listedOpen ? 'Found in OpenPhish feed' : 'Not in feed' });
    details.openphish = { listed: !!listedOpen };
  } catch {
    parts.push({ source: 'openphish', score: 0, reason: 'Feed unavailable' });
  }

  try {
    let listedPT = false;
    if (Array.isArray(phishTank)) {
      listedPT = phishTank.some(entry => entry.url && (entry.url === normalized || entry.url === u.origin));
    }
    parts.push({ source: 'phishtank', score: listedPT ? 100 : 0, reason: listedPT ? 'Found in PhishTank feed' : 'Not in feed' });
    details.phishtank = { listed: !!listedPT };
  } catch {
    parts.push({ source: 'phishtank', score: 0, reason: 'Feed unavailable' });
  }

  // Heuristics
  const dnsInfo = await basicDns(domain);
  const headInfo = await headFollow(normalized);
  details.dns = dnsInfo;
  details.http_head = headInfo;

  let heurScore = 0;
  if (!dnsInfo.ok) heurScore += 20;
  if (!headInfo.ok) heurScore += 20;
  if (headInfo.ok && headInfo.status >= 400) heurScore += 15;
  // very long subdomain or multi-level
  if (domain.split('.').length > 3 && domain.length > 40) heurScore += 10;
  // suspicious query params
  const suspiciousParams = ['login','update','verify','account','secure','bank','wallet','password'];
  const hasSusp = suspiciousParams.some(k => u.search.toLowerCase().includes(k));
  if (hasSusp) heurScore += 10;
  parts.push({ source: 'heur', score: Math.min(heurScore, 100), reason: 'Heuristic checks' });

  // WHOIS (for report only)
  try {
    const who = await getWhois(domain);
    details.whois = who;
  } catch {}

  const combined = combineScores(parts);
  const result = {
    input: normalized,
    domain,
    status: combined.status,
    score: combined.score,
    parts: combined.detail,
    details
  };

  return {
    statusCode: 200,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(result)
  };
};
