\
const dns = require('dns');
const { promisify } = require('util');
const fetch = require('node-fetch');
const whoisJson = require('whois-json');

const resolve4 = promisify(dns.resolve4);

function normalizeUrl(u) {
  try {
    let url = new URL(u.trim());
    return url.toString();
  } catch (e) {
    try {
      // try add https:// if missing
      let url = new URL('https://' + u.trim());
      return url.toString();
    } catch {
      return null;
    }
  }
}

async function basicDns(hostname) {
  try {
    const addrs = await resolve4(hostname);
    return { ok: true, addresses: addrs };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

async function headFollow(url) {
  try {
    const res = await fetch(url, { method: 'HEAD', redirect: 'follow' });
    return {
      ok: true,
      finalUrl: res.url,
      status: res.status,
      contentType: res.headers.get('content-type') || null
    };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

async function getWhois(hostname) {
  try {
    const data = await whoisJson(hostname, { follow: 2 });
    return data;
  } catch (e) {
    return { error: e.message };
  }
}

module.exports = { normalizeUrl, basicDns, headFollow, getWhois };
