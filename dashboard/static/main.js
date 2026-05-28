/* ══════════════════════════════════════════════════════════════
   DDoS Mitigation System — Dashboard JS
   Modules: SSE · Traffic Chart · Entropy Gauges · CMS Heatmap
            Attack Control · Threat Table · SYN Cookie Log · Anomaly Chart
   ══════════════════════════════════════════════════════════════ */

// ── 1. SSE handler ────────────────────────────────────────────
const evtSource = new EventSource('/stream');
evtSource.onmessage = (ev) => {
  const data = JSON.parse(ev.data);
  updateHeaderStats(data.pps);
  updateTrafficChart(data.pps);
  updateEntropy(data.entropy);
  drawCMS(data.cms_snapshot);
  updateThreatTable(data.top_talkers);
  updateCookieLog(data.syn_cookie_events);
  updateAnomalyChart(data.z_score);
  updateAttackStatus(data.attack_status);
  updateMitigationLog(data.mitigation_log);
  updateSystemLog(data.system_log);
  updateKPIs(data);
};

evtSource.onerror = () => console.warn('SSE disconnected — retrying…');

// ── 2. Header stats ───────────────────────────────────────────
function updateHeaderStats(pps) {
  ['SYN', 'UDP', 'ICMP', 'total'].forEach(k => {
    const el = document.getElementById(`hdr-${k.toLowerCase()}`);
    if (el) el.textContent = Math.round(pps[k] || 0);
  });
}

// ── 2b. KPI chips (threats / blocked / uptime) ────────────────
function fmtUptime(sec) {
  sec = Math.max(0, sec | 0);
  const h = String((sec / 3600) | 0).padStart(2, '0');
  const m = String(((sec % 3600) / 60) | 0).padStart(2, '0');
  const s = String(sec % 60).padStart(2, '0');
  return `${h}:${m}:${s}`;
}

function updateKPIs(data) {
  const threats = (data.top_talkers || []).filter(t => (t.tier || 'MONITOR') !== 'MONITOR').length;
  const blocked = (data.blocked || []).length;
  const setTxt = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  setTxt('hdr-threats', threats);
  setTxt('hdr-blocked', blocked);
  setTxt('hdr-uptime', fmtUptime(data.uptime || 0));

  const blkChip = document.getElementById('hdr-blocked')?.closest('.stat-chip');
  if (blkChip) blkChip.classList.toggle('active', blocked > 0);
}

// ── 3. Traffic Chart (Chart.js) ───────────────────────────────
const ROLLING = 60;
const trafficLabels = Array(ROLLING).fill('');
const trafficSets = {
  SYN:   Array(ROLLING).fill(0),
  UDP:   Array(ROLLING).fill(0),
  ICMP:  Array(ROLLING).fill(0),
  total: Array(ROLLING).fill(0),
};

const trafficChart = new Chart(
  document.getElementById('traffic-canvas').getContext('2d'),
  {
    type: 'line',
    data: {
      labels: trafficLabels,
      datasets: [
        { label: 'SYN',   data: trafficSets.SYN,   borderColor: '#ff3366', backgroundColor: 'rgba(255,51,102,0.06)',  fill: true, tension: 0.3, pointRadius: 0 },
        { label: 'UDP',   data: trafficSets.UDP,   borderColor: '#ff8c00', backgroundColor: 'rgba(255,140,0,0.06)',   fill: true, tension: 0.3, pointRadius: 0 },
        { label: 'ICMP',  data: trafficSets.ICMP,  borderColor: '#9b59b6', backgroundColor: 'rgba(155,89,182,0.06)',  fill: true, tension: 0.3, pointRadius: 0 },
        { label: 'Total', data: trafficSets.total, borderColor: '#00d4ff', backgroundColor: 'rgba(0,212,255,0.04)',   fill: true, tension: 0.3, pointRadius: 0 },
      ],
    },
    options: {
      animation: false,
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      scales: {
        x: { display: false },
        y: {
          beginAtZero: true,
          grid: { color: 'rgba(255,255,255,0.04)' },
          ticks: { color: '#556070', font: { family: 'JetBrains Mono', size: 9 } },
        },
      },
      plugins: {
        legend: { labels: { color: '#888', font: { family: 'JetBrains Mono', size: 10 }, boxWidth: 10 } },
      },
    },
  }
);

function updateTrafficChart(pps) {
  ['SYN', 'UDP', 'ICMP', 'total'].forEach(k => {
    trafficSets[k].push(pps[k] || 0);
    trafficSets[k].shift();
  });
  trafficChart.update('none');
}

// ── 4. Entropy Gauges (D3 arc) ────────────────────────────────
function buildGauge(selector, subtitle) {
  const W = 160, H = 160, Ro = 68, Ri = 50;
  const startA = -Math.PI * 0.75, endA = Math.PI * 0.75;

  const svg = d3.select(selector)
    .append('svg').attr('width', W).attr('height', H);
  const g = svg.append('g').attr('transform', `translate(${W/2},${H/2+8})`);

  // Background track
  const bgArc = d3.arc().innerRadius(Ri).outerRadius(Ro).startAngle(startA).endAngle(endA);
  g.append('path').attr('d', bgArc()).attr('fill', '#111a2e');

  // Foreground arc
  const fgPath = g.append('path').attr('fill', '#00ff88');

  // Center value label
  const valLabel = g.append('text')
    .attr('text-anchor', 'middle').attr('fill', '#00ff88')
    .attr('font-size', '22px').attr('font-family', 'JetBrains Mono')
    .attr('dy', '0.35em').text('0.0');

  // Subtitle
  g.append('text')
    .attr('text-anchor', 'middle').attr('fill', '#556070')
    .attr('font-size', '9px').attr('font-family', 'JetBrains Mono')
    .attr('dy', '1.9em').text(subtitle);

  const arcFn = d3.arc().innerRadius(Ri).outerRadius(Ro).startAngle(startA);

  return { fgPath, valLabel, arcFn, startA, endA };
}

function updateGauge(gauge, value, max = 8) {
  const pct = Math.min(1, value / max);
  const angle = gauge.startA + pct * (gauge.endA - gauge.startA);
  const color = value < 3.5 ? '#00ff88' : value < 6 ? '#ff8c00' : '#ff3366';

  gauge.fgPath
    .transition().duration(600)
    .attr('d', gauge.arcFn.endAngle(angle)())
    .attr('fill', color);

  gauge.valLabel
    .text(value.toFixed(1))
    .attr('fill', color);
}

const srcGauge = buildGauge('#entropy-src-gauge', 'src /24 prefix H');
const dstGauge = buildGauge('#entropy-dst-gauge', 'dst port H');

function updateEntropy(entropy) {
  updateGauge(srcGauge, entropy.src_prefix || 0);
  updateGauge(dstGauge, entropy.dst_port    || 0);
}

// ── 5. CMS Heatmap (Canvas 2D) ───────────────────────────────
const cmsCanvas = document.getElementById('cms-canvas');
const cmsCtx    = cmsCanvas.getContext('2d');

function drawCMS(snapshot) {
  if (!snapshot || !snapshot.length) return;
  const rows = snapshot.length;
  const cols = snapshot[0].length;

  const W = cmsCanvas.offsetWidth  || 260;
  const H = cmsCanvas.offsetHeight || 110;
  cmsCanvas.width  = W;
  cmsCanvas.height = H;

  const ML = 18, MT = 14, MR = 4, MB = 10;
  const cellW = (W - ML - MR) / cols;
  const cellH = (H - MT - MB) / rows;

  cmsCtx.fillStyle = '#0a0e1a';
  cmsCtx.fillRect(0, 0, W, H);

  let maxVal = 1;
  for (const row of snapshot) for (const v of row) if (v > maxVal) maxVal = v;

  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      const v   = snapshot[r][c];
      const L   = v === 0 ? 3 : Math.max(8, Math.min(50, (v / maxVal) * 50));
      cmsCtx.fillStyle = v === 0 ? '#0d121f' : `hsl(140,100%,${L}%)`;
      cmsCtx.fillRect(ML + c * cellW + 0.5, MT + r * cellH + 0.5, cellW - 1, cellH - 1);
    }
    // Row label
    cmsCtx.fillStyle = '#445060';
    cmsCtx.font = '8px JetBrains Mono';
    cmsCtx.fillText(r, 2, MT + r * cellH + cellH / 2 + 3);
  }

  // Column labels (every 4)
  for (let c = 0; c < cols; c += 4) {
    cmsCtx.fillStyle = '#445060';
    cmsCtx.font = '7px JetBrains Mono';
    cmsCtx.fillText(c, ML + c * cellW, MT - 3);
  }
}

// ── 6. Threat Score Table ─────────────────────────────────────
function updateThreatTable(topTalkers) {
  const tbody = document.getElementById('threat-tbody');
  tbody.innerHTML = '';

  for (const t of topTalkers) {
    const comp  = t.components || {};
    const score = Math.round(t.score || 0);
    const tier  = (t.tier || 'MONITOR');
    const cls   = tier.toLowerCase().replace('_', '-');

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="font-size:9px;color:#aac">${t.ip}</td>
      <td><span class="tier-badge tier-${cls}">${tier}</span></td>
      <td style="color:var(--cyan);font-weight:700">${score}</td>
      <td>
        <div class="score-bar" title="rate:${Math.round(comp.rate||0)} entropy:${Math.round(comp.entropy||0)} anomaly:${Math.round(comp.anomaly||0)} rep:${Math.round(comp.reputation||0)}">
          <div class="bar-rate"       style="width:${comp.rate       || 0}%"></div>
          <div class="bar-entropy"    style="width:${comp.entropy    || 0}%"></div>
          <div class="bar-anomaly"    style="width:${comp.anomaly    || 0}%"></div>
          <div class="bar-reputation" style="width:${comp.reputation || 0}%"></div>
        </div>
      </td>`;
    tbody.appendChild(tr);
  }
}

// ── 7. SYN Cookie Log ────────────────────────────────────────
const _seenCookies = new Set();

function updateCookieLog(events) {
  const container = document.getElementById('cookie-log-entries');
  if (!events) return;

  for (const ev of events) {
    const key = `${ev.ts}|${ev.ip}|${ev.result}`;
    if (_seenCookies.has(key)) continue;
    _seenCookies.add(key);

    const d   = new Date(ev.ts * 1000);
    const ts  = d.toTimeString().slice(0, 8);
    const cls = { VALID: 'cookie-valid', FAIL: 'cookie-fail', MISS: 'cookie-miss' }[ev.result] || '';

    const entry = document.createElement('div');
    entry.className = `cookie-entry ${cls}`;
    entry.textContent = `${ts}  ${ev.ip}  →  ${ev.result}`;
    container.insertBefore(entry, container.firstChild);

    while (container.children.length > 50) container.removeChild(container.lastChild);
  }
}

// ── 7b. Mitigation Log (tier transitions) ────────────────────
function updateMitigationLog(entries) {
  const container = document.getElementById('mitigation-log-entries');
  if (!container || !entries) return;

  container.innerHTML = entries.slice(-60).reverse().map(ev => {
    const cls = `tier-${(ev.tier || 'monitor').toLowerCase().replace('_', '-')}`;
    return `<div class="mit-entry ${cls}">`
      + `<span class="mit-ts">${ev.ts}</span>`
      + `<span class="mit-ip">${ev.ip}</span>`
      + `<span class="mit-arrow">${ev.prev} → <b>${ev.tier}</b></span>`
      + `<span class="mit-score">${ev.score}</span>`
      + `</div>`;
  }).join('');
}

// ── 7c. System Log (pipeline console) ────────────────────────
function updateSystemLog(entries) {
  const container = document.getElementById('system-log-entries');
  if (!container) return;

  const prompt = `<div class="sys-prompt">monitor@ddos:~$ tail -f /var/log/pipeline <span class="sys-cursor">█</span></div>`;
  if (!entries || !entries.length) { container.innerHTML = prompt; return; }

  container.innerHTML = prompt + entries.slice(-80).reverse().map(ev => {
    const lvl = (ev.level || 'info').toLowerCase();
    return `<div class="sys-entry sys-${lvl}">`
      + `<span class="sys-ts">${ev.ts}</span>`
      + `<span class="sys-lvl">[${ev.level}]</span>`
      + `<span class="sys-msg">${ev.msg}</span>`
      + `</div>`;
  }).join('');
}

// ── 8. Anomaly Z-Score Chart ──────────────────────────────────
const anomalyData      = Array(ROLLING).fill(0);
const anomalyThreshold = Array(ROLLING).fill(3);

const anomalyChart = new Chart(
  document.getElementById('anomaly-canvas').getContext('2d'),
  {
    type: 'line',
    data: {
      labels: Array(ROLLING).fill(''),
      datasets: [
        {
          label: 'z-score',
          data: anomalyData,
          borderColor: '#00d4ff',
          backgroundColor: 'rgba(0,212,255,0.06)',
          fill: true, tension: 0.4, pointRadius: 0,
        },
        {
          label: '3σ',
          data: anomalyThreshold,
          borderColor: '#ff3366',
          borderDash: [5, 4],
          fill: false, pointRadius: 0,
        },
      ],
    },
    options: {
      animation: false,
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { display: false },
        y: {
          beginAtZero: true,
          grid: { color: 'rgba(255,255,255,0.04)' },
          ticks: { color: '#556070', font: { family: 'JetBrains Mono', size: 9 } },
        },
      },
      plugins: {
        legend: { display: false },
      },
    },
  }
);

function updateAnomalyChart(zScore) {
  const z = zScore || 0;
  anomalyData.push(z);
  anomalyData.shift();
  anomalyChart.update('none');

  const zEl = document.getElementById('z-value');
  if (zEl) zEl.textContent = `${z.toFixed(2)} σ`;

  const alert = document.getElementById('anomaly-alert');
  if (z > 3) {
    alert.classList.remove('hidden');
  } else {
    alert.classList.add('hidden');
  }
}

// ── 9. Attack Control ─────────────────────────────────────────
function startAttack(type) {
  const rate      = parseInt(document.getElementById('rate-slider').value, 10);
  const duration  = parseInt(document.getElementById('dur-slider').value, 10);
  const target    = document.getElementById('target-input').value;
  const fixedSrc  = document.getElementById('fixed-src-check')?.checked && type === 'syn';

  fetch('/api/attack/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type, rate, duration, target, fixed_src: fixedSrc }),
  }).catch(e => console.error(e));

  document.querySelectorAll('.attack-btn').forEach(b => {
    b.classList.remove('active');
    b.disabled = (b.id !== `btn-${type}`);
  });
  const btn = document.getElementById(`btn-${type}`);
  if (btn) btn.classList.add('active');
}

function stopAttack() {
  fetch('/api/attack/stop', { method: 'POST' }).catch(e => console.error(e));
  document.querySelectorAll('.attack-btn').forEach(b => {
    b.classList.remove('active');
    b.disabled = false;
  });
}

function updateAttackStatus(status) {
  const badge = document.getElementById('attack-badge');
  if (!badge) return;
  if (status && status.running) {
    badge.classList.remove('hidden');
    badge.textContent = `● ${status.type} RUNNING  PID ${status.pid}`;
  } else {
    badge.classList.add('hidden');
    document.querySelectorAll('.attack-btn').forEach(b => {
      b.classList.remove('active');
      b.disabled = false;
    });
  }
}
