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
