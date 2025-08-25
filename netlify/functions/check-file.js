<<<<<<< HEAD
const Busboy = require('busboy');
const fetch = require('node-fetch');
const FormData = require('form-data');

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

  try {
    const fileBuffer = await parseFile(event);
    if (!fileBuffer) {
      return {
        statusCode: 400,
        headers: { 'Access-Control-Allow-Origin': '*' },
        body: JSON.stringify({ error: 'No file uploaded' }),
      };
    }

    const vt = await scanWithVirusTotal(fileBuffer);

    return {
      statusCode: 200,
      headers: { 'Access-Control-Allow-Origin': '*' },
      body: JSON.stringify({ results: [vt] }),
    };
  } catch (error) {
    console.error('check-file error:', error);
    return {
      statusCode: 500,
      headers: { 'Access-Control-Allow-Origin': '*' },
      body: JSON.stringify({ error: error.message }),
    };
  }
};

function parseFile(event) {
  return new Promise((resolve, reject) => {
    try {
      const headers = event.headers || {};
      const contentType = headers['content-type'] || headers['Content-Type'];
      if (!contentType) return resolve(null);

      const busboy = new Busboy({ headers: { 'content-type': contentType } });
      let chunks = [];

      busboy.on('file', (fieldname, file) => {
        file.on('data', (data) => chunks.push(data));
      });

      busboy.on('finish', () => {
        const buffer = Buffer.concat(chunks);
        resolve(buffer.length ? buffer : null);
      });

      busboy.on('error', (err) => reject(err));

      const body = Buffer.from(event.body || '', event.isBase64Encoded ? 'base64' : 'utf8');
      busboy.end(body);
    } catch (e) {
      reject(e);
    }
  });
}

async function scanWithVirusTotal(fileBuffer) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return { service: 'VirusTotal', status: 'warning', details: 'VIRUSTOTAL_API_KEY не установлен' };
  }

  // upload
  const form = new FormData();
  form.append('file', fileBuffer, { filename: 'uploaded_file' });

  const uploadRes = await fetch('https://www.virustotal.com/vtapi/v2/file/scan', {
    method: 'POST',
    headers: { 'apikey': apiKey },
    body: form,
  });

  if (!uploadRes.ok) {
    return { service: 'VirusTotal', status: 'warning', details: `Ошибка загрузки: ${uploadRes.status}` };
  }

  const uploadData = await uploadRes.json();
  const resource = uploadData.resource || uploadData.sha256 || uploadData.sha1;

  // poll for report (limited to keep function within time limits)
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  let reportData = null;
  for (let i = 0; i < 3; i++) {
    await sleep(i === 0 ? 4000 : 3000);
    const reportRes = await fetch(`https://www.virustotal.com/vtapi/v2/file/report?apikey=${apiKey}&resource=${encodeURIComponent(resource)}`);
    if (!reportRes.ok) continue;
    const data = await reportRes.json();
    if (data && data.response_code === 1) { reportData = data; break; }
    if (data && data.response_code === -2) { /* still queued */ }
  }

  if (!reportData) {
    const permalink = uploadData.permalink || '';
    return {
      service: 'VirusTotal',
      status: 'warning',
      details: `Репорт ещё не готов. Проверьте позже. ${permalink ? 'Permalink: ' + permalink : ''}`
    };
  }

  const positives = reportData.positives || 0;
  const total = reportData.total || 0;
  const status = positives > 0 ? 'unsafe' : 'safe';
  return {
    service: 'VirusTotal',
    status,
    details: positives > 0
      ? `${positives} из ${total} антивирусов обнаружили угрозы`
      : 'Угроз не обнаружено'
  };
}
=======
\
const fetch = require('node-fetch');
const crypto = require('crypto');

const VT_KEY = process.env.VIRUSTOTAL_API_KEY;

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }
  if (!VT_KEY) {
    return { statusCode: 500, body: JSON.stringify({ error: 'VIRUSTOTAL_API_KEY not set' }) };
  }
  const contentType = event.headers['content-type'] || event.headers['Content-Type'] || '';
  if (!contentType.startsWith('application/octet-stream')) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Send raw file bytes with application/octet-stream' }) };
  }

  const buff = Buffer.from(event.body, event.isBase64Encoded ? 'base64' : 'utf8');
  const sha256 = crypto.createHash('sha256').update(buff).digest('hex');

  let vtDetail = null;
  let vtScore = 0;

  try {
    const hashRes = await fetch(`https://www.virustotal.com/api/v3/files/${sha256}`, {
      headers: { 'x-apikey': VT_KEY }
    });
    if (hashRes.status === 200) {
      const j = await hashRes.json();
      vtDetail = j;
      const stats = j.data?.attributes?.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      vtScore = Math.min(100, (malicious * 10) + (suspicious * 5));
    } else if (hashRes.status === 404) {
      // Upload new file (multipart/form-data)
      const boundary = '----DefenderLinkBoundary' + Math.random().toString(16).slice(2);
      const head = Buffer.from(
        `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="file"; filename="upload.bin"\r\n` +
        `Content-Type: application/octet-stream\r\n\r\n`
      );
      const tail = Buffer.from(`\r\n--${boundary}--\r\n`);
      const body = Buffer.concat([head, buff, tail]);
      const upRes = await fetch('https://www.virustotal.com/api/v3/files', {
        method: 'POST',
        headers: { 'x-apikey': VT_KEY, 'Content-Type': `multipart/form-data; boundary=${boundary}` },
        body
      });
      vtDetail = await upRes.json();
      vtScore = 0; // analysis pending on VT
    } else {
      vtDetail = { error: `VT returned ${hashRes.status}` };
    }
  } catch (e) {
    vtDetail = { error: e.message };
  }

  const status = vtScore >= 70 ? 'danger' : vtScore >= 30 ? 'suspicious' : 'safe';
  const result = {
    hash: sha256,
    status,
    score: vtScore,
    details: { virustotal: vtDetail }
  };

  return {
    statusCode: 200,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(result)
  };
};
>>>>>>> 5fd1a73e7c785353bb4c6313239887405cef94c3
