<<<<<<< HEAD
const fetch = require('node-fetch');

exports.handler = async (event) => {
  // CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
      },
      body: '',
    };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  let url;
  try {
    ({ url } = JSON.parse(event.body || '{}'));
  } catch (e) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Bad JSON' }) };
  }

  if (!url) {
    return { statusCode: 400, body: JSON.stringify({ error: 'URL is required' }) };
  }

  try {
    const [googleResult, virusTotalResult, phishTankResult, openPhishResult] = await Promise.all([
      checkGoogleSafeBrowsing(url),
      checkVirusTotalUrl(url),
      checkPhishTank(url),
      checkOpenPhish(url),
    ]);

    const results = [
      {
        service: 'Google Safe Browsing',
        status: googleResult.safe ? 'safe' : 'unsafe',
        details: googleResult.details,
      },
      {
        service: 'VirusTotal',
        status: virusTotalResult.status,
        details: virusTotalResult.details,
      },
      {
        service: 'PhishTank',
        status: phishTankResult.safe ? 'safe' : 'unsafe',
        details: phishTankResult.details,
      },
      {
        service: 'OpenPhish',
        status: openPhishResult.safe ? 'safe' : 'unsafe',
        details: openPhishResult.details,
      },
    ];

    return {
      statusCode: 200,
      headers: { 'Access-Control-Allow-Origin': '*' },
      body: JSON.stringify({ url, results }),
    };
  } catch (error) {
    console.error('check-url error:', error);
    return {
      statusCode: 500,
      headers: { 'Access-Control-Allow-Origin': '*' },
      body: JSON.stringify({ error: error.message }),
    };
  }
};

// Google Safe Browsing v4
async function checkGoogleSafeBrowsing(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!apiKey) throw new Error('GOOGLE_SAFE_BROWSING_KEY is not set');

  const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
  const requestBody = {
    client: { clientId: 'defenderlink-app', clientVersion: '1.0.0' },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'POTENTIALLY_HARMFUL_APPLICATION', 'UNWANTED_SOFTWARE', 'PHISHING'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }],
    },
  };

  const response = await fetch(apiUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    const t = await response.text();
    throw new Error(`GSB error: ${response.status} ${t}`);
  }

  const data = await response.json();
  return {
    safe: !data.matches || data.matches.length === 0,
    details: data.matches ? `Обнаружены угрозы: ${data.matches.map((m) => m.threatType).join(', ')}` : 'Угроз не обнаружено',
  };
}

// VirusTotal URL report (v2)
async function checkVirusTotalUrl(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return { status: 'warning', details: 'VIRUSTOTAL_API_KEY не установлен' };

  const apiUrl = `https://www.virustotal.com/vtapi/v2/url/report?apikey=${apiKey}&resource=${encodeURIComponent(url)}`;
  const response = await fetch(apiUrl);
  if (!response.ok) {
    return { status: 'warning', details: `VirusTotal недоступен: ${response.status}` };
  }

  const data = await response.json();
  if (data.response_code === 1) {
    const positives = data.positives || 0;
    const total = data.total || 0;
    const status = positives > 0 ? 'unsafe' : 'safe';
    return { status, details: `${positives} из ${total} антивирусов обнаружили угрозы` };
  }
  if (data.response_code === -2) {
    return { status: 'warning', details: 'Отчёт ещё не готов. Повторите позже.' };
  }
  return { status: 'warning', details: 'Результат проверки недоступен' };
}

// PhishTank
async function checkPhishTank(url) {
  const apiUrl = 'https://checkurl.phishtank.com/checkurl/';
  const params = new URLSearchParams({ url, format: 'json' });
  if (process.env.PHISHTANK_API_KEY) {
    params.append('app_key', process.env.PHISHTANK_API_KEY);
  }

  try {
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params,
    });
    if (!response.ok) {
      return { safe: true, details: 'PhishTank временно недоступен' };
    }
    const data = await response.json();
    const inDb = data?.results?.in_database === true;
    return {
      safe: !inDb,
      details: inDb ? 'URL найден в базе фишинговых сайтов' : 'URL не найден в базе фишинговых сайтов',
    };
  } catch (e) {
    return { safe: true, details: 'PhishTank недоступен' };
  }
}

// OpenPhish feed exact match
async function checkOpenPhish(url) {
  const normalize = (u) => {
    try {
      const s = String(u).trim();
      return s.replace(/\/+$/, '').toLowerCase();
    } catch { return String(u || '').trim().toLowerCase(); }
  };

  const target = normalize(url);
  const response = await fetch('https://openphish.com/feed.txt');
  if (!response.ok) return { safe: true, details: 'OpenPhish недоступен' };

  const text = await response.text();
  const set = new Set(text.split('\n').map((line) => normalize(line)).filter(Boolean));
  const found = set.has(target);

  return {
    safe: !found,
    details: found ? 'URL найден в базе OpenPhish' : 'URL не найден в базе OpenPhish',
  };
}
=======
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
>>>>>>> 5fd1a73e7c785353bb4c6313239887405cef94c3
