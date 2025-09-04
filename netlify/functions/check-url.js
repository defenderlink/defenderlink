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

