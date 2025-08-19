\
function combineScores(parts) {
  const weights = { gsb: 0.40, vt: 0.35, openphish: 0.12, phishtank: 0.08, heur: 0.05 };
  let score = 0;
  const detail = {};
  for (const p of parts) {
    const w = weights[p.source] ?? 0.05;
    const s = Math.max(0, Math.min(100, p.score || 0));
    score += s * w;
    detail[p.source] = { score: Math.round(s), reason: p.reason || '' };
  }
  const total = Math.round(score);
  const status = total >= 70 ? 'danger' : total >= 30 ? 'suspicious' : 'safe';
  return { status, score: total, detail };
}

module.exports = { combineScores };
