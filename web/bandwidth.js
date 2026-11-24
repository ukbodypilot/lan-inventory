/* Per-device bandwidth block for the Devices page (index.html) and the Clients drawer (router-clients.html).
   Standalone (index.html does not load console.js). Data: api/history (client_down/client_up, hourly averages)
   and api/usage (estimated bytes per day, router_history.usage). Rates are the Deco's own numbers, assumed kB/s. */
(function () {
  'use strict';
  var BW = window.BW = {};
  var cache = {}, TTL = 5 * 60 * 1000, DAYS = 7;

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function getJSON(path) {
    return fetch(path, { cache: 'no-store' }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  }

  BW.fmtBytes = function (b) {
    if (b == null) return '–';
    if (b >= 1e12) return (b / 1e12).toFixed(2) + ' TB';
    if (b >= 1e9) return (b / 1e9).toFixed(b >= 1e10 ? 0 : 1) + ' GB';
    if (b >= 1e6) return (b / 1e6).toFixed(b >= 1e7 ? 0 : 1) + ' MB';
    if (b >= 1e3) return Math.round(b / 1e3) + ' kB';
    return b > 0 ? '<1 kB' : '0';
  };
  BW.fmtRate = function (v) {  // v in the Deco's unit (assumed kB/s)
    if (v == null) return '–';
    if (v >= 1000) return (v / 1000).toFixed(v >= 10000 ? 0 : 1) + ' MB/s';
    return Math.round(v) + ' kB/s';
  };

  BW.load = function (mac) {
    mac = mac.toLowerCase();
    var c = cache[mac];
    if (c && (c.data || c.pending) && Date.now() - c.at < TTL) return c.pending || Promise.resolve(c.data);
    var since = DAYS * 86400, k = '&key=' + encodeURIComponent(mac);
    var p = Promise.all([
      getJSON('api/history?metric=client_down&since=' + since + '&points=' + DAYS * 24 + k),
      getJSON('api/history?metric=client_up&since=' + since + '&points=' + DAYS * 24 + k),
      getJSON('api/usage?since=' + (14 * 86400) + k)
    ]).then(function (r) {
      var data = { down: (r[0].series || {})[mac] || [], up: (r[1].series || {})[mac] || [],
                   days: (r[2].usage || {})[mac] || [], maxGap: r[2].max_gap };
      cache[mac] = { at: Date.now(), data: data };
      return data;
    }, function (e) { delete cache[mac]; throw e; });
    cache[mac] = { at: Date.now(), pending: p };
    return p;
  };

  // Two-series chart (down = filled area, up = line) over the last DAYS days, one point per hour.
  function chart(down, up) {
    var W = 1000, H = 110, end = Date.now() / 1000, start = end - DAYS * 86400, step = 3600;
    var hi = 0;
    down.concat(up).forEach(function (p) { if (p[1] > hi) hi = p[1]; });
    if (hi <= 0) hi = 1;
    function x(t) { return ((t - start) / (end - start) * W).toFixed(1); }
    function y(v) { return (H - 2 - v / hi * (H - 6)).toFixed(1); }
    // a gap of more than two buckets between points = no samples (offline or collector down): break the line
    function segs(s) {
      var out = [], cur = [];
      s.forEach(function (p, i) {
        if (i && p[0] - s[i - 1][0] > 2 * step) { if (cur.length) out.push(cur); cur = []; }
        cur.push(p);
      });
      if (cur.length) out.push(cur);
      return out;
    }
    var area = segs(down).map(function (sg) {
      return '<polygon points="' + x(sg[0][0]) + ',' + H + ' ' + sg.map(function (p) { return x(p[0]) + ',' + y(p[1]); }).join(' ') +
        ' ' + x(sg[sg.length - 1][0]) + ',' + H + '" fill="var(--acc)" fill-opacity=".22"/>' +
        '<polyline points="' + sg.map(function (p) { return x(p[0]) + ',' + y(p[1]); }).join(' ') +
        '" fill="none" stroke="var(--acc)" stroke-width="1.5" vector-effect="non-scaling-stroke"/>';
    }).join('');
    var line = segs(up).map(function (sg) {
      return '<polyline points="' + sg.map(function (p) { return x(p[0]) + ',' + y(p[1]); }).join(' ') +
        '" fill="none" stroke="var(--amber)" stroke-width="1.5" vector-effect="non-scaling-stroke"/>';
    }).join('');
    // midnight gridlines
    var grid = '', labels = '', d = new Date(start * 1000); d.setHours(24, 0, 0, 0);
    for (; d.getTime() / 1000 < end; d.setDate(d.getDate() + 1)) {
      var t = d.getTime() / 1000;
      grid += '<line x1="' + x(t) + '" x2="' + x(t) + '" y1="0" y2="' + H + '" stroke="var(--line)" stroke-width="1" vector-effect="non-scaling-stroke"/>';
      labels += '<span style="left:' + (x(t) / 10) + '%">' + esc(d.toLocaleDateString([], { weekday: 'short' })) + '</span>';
    }
    return '<div class="bw-chart"><div class="bw-max">' + esc(BW.fmtRate(hi)) + '</div>' +
      '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" width="100%" height="' + H + '" role="img" aria-label="Download and upload rate, last ' + DAYS + ' days">' +
      grid + area + line + '</svg><div class="bw-x">' + labels + '</div></div>';
  }

  function recent(days) {  // buckets that start within the last DAYS calendar days (today included)
    var d = new Date(); d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - (DAYS - 1));
    var cut = d.getTime() / 1000;
    return days.filter(function (r) { return r[0] >= cut; });
  }

  function dayBars(days) {
    var rows = recent(days).reverse();
    if (!rows.length) return '<p class="bw-note">No samples yet.</p>';
    var hi = Math.max.apply(null, rows.map(function (r) { return r[1] + r[2]; })) || 1;
    return '<div class="bw-wrap"><table class="bw-days"><tbody>' + rows.map(function (r) {
      var d = new Date(r[0] * 1000), tot = r[1] + r[2], cov = Math.min(1, r[3] / 86400);
      var today = d.toDateString() === new Date().toDateString();
      return '<tr><td>' + esc(today ? 'Today' : d.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' })) + '</td>' +
        '<td class="bw-bar"><i style="width:' + (r[1] / hi * 100).toFixed(1) + '%;background:var(--acc)"></i>' +
          '<i style="width:' + (r[2] / hi * 100).toFixed(1) + '%;background:var(--amber)"></i></td>' +
        '<td class="bw-num" title="↓' + esc(BW.fmtBytes(r[1])) + ' ↑' + esc(BW.fmtBytes(r[2])) + '">' + esc(BW.fmtBytes(tot)) + '</td>' +
        '<td class="bw-sub">↓' + esc(BW.fmtBytes(r[1])) + ' ↑' + esc(BW.fmtBytes(r[2])) +
          (!today && cov < 0.9 ? ' · ' + Math.round(cov * 100) + '% of day sampled' : '') + '</td></tr>';
    }).join('') + '</tbody></table></div>';
  }

  BW.html = function (data) {
    var any = data.down.length || data.up.length;
    var wk = recent(data.days).reduce(function (a, r) { return a + r[1] + r[2]; }, 0);
    return '<div class="bw-head"><h3>Bandwidth, last ' + DAYS + ' days</h3>' +
        '<span class="bw-legend"><i style="background:var(--acc)"></i>down <i style="background:var(--amber)"></i>up · ' +
        esc(BW.fmtBytes(wk)) + ' in ' + DAYS + ' days</span></div>' +
      (any ? chart(data.down, data.up) : '<p class="bw-note">The router has reported no traffic for this device in the last ' + DAYS + ' days.</p>') +
      '<h3 class="bw-h3">Data per day (estimate)</h3>' + dayBars(data.days) +
      '<p class="bw-note">The router only reports a device\'s speed at each 5-minute read, not a byte count, so the daily totals ' +
        'assume that speed held until the next read. Short bursts between reads are missed. Hourly averages in the chart; ' +
        'speeds are the router\'s numbers, read as kB/s (unit not yet confirmed).</p>';
  };

  // Fill every [data-bw="<mac>"] under root. Safe to call after each re-render: cached for 5 minutes.
  BW.fill = function (root) {
    Array.prototype.forEach.call((root || document).querySelectorAll('[data-bw]'), function (el) {
      var mac = el.getAttribute('data-bw'), c = cache[mac.toLowerCase()];
      if (c && c.data) el.innerHTML = BW.html(c.data);
      else if (!el.innerHTML) el.innerHTML = '<p class="bw-note">Loading bandwidth…</p>';
      BW.load(mac).then(function (d) {
        if (el.isConnected) el.innerHTML = BW.html(d);
      }, function (e) {
        if (el.isConnected) el.innerHTML = '<p class="bw-note">Bandwidth unavailable (' + esc(e.message) + ').</p>';
      });
    });
  };

  // Estimated bytes per MAC over the last `since` seconds: {mac: {down, up}} (for list columns)
  BW.totals = function (since) {
    return getJSON('api/usage?since=' + since + '&bucket=3600').then(function (j) {
      var out = {}, cut = Date.now() / 1000 - since;
      Object.keys(j.usage || {}).forEach(function (m) {
        var t = { down: 0, up: 0 };
        j.usage[m].forEach(function (r) { if (r[0] >= cut - 3600) { t.down += r[1]; t.up += r[2]; } });
        out[m] = t;
      });
      return out;
    });
  };

  var css = document.createElement('style');
  css.textContent =
    '.bw-head{display:flex;flex-wrap:wrap;align-items:baseline;justify-content:space-between;gap:8px}' +
    '.bw-head h3{margin:0}.bw-legend{font-size:12px;color:var(--mut)}' +
    '.bw-legend i{display:inline-block;width:10px;height:4px;border-radius:2px;margin:0 3px 2px 6px;vertical-align:middle}' +
    '.bw-chart{position:relative;margin-top:8px;border-bottom:1px solid var(--line)}' +
    '.bw-max{position:absolute;top:0;left:4px;font-size:11px;color:var(--mut);font-family:var(--font-mono);pointer-events:none}' +
    '.bw-chart svg{display:block}' +
    '.bw-x{position:relative;height:16px;font-size:11px;color:var(--mut)}.bw-x span{position:absolute;top:2px;padding-left:3px}' +
    '.bw-h3{margin:14px 0 6px !important}' +
    '.bw-wrap{container-type:inline-size}' +
    'table.bw-days{border-collapse:collapse;width:100%;font-size:13px;background:none;margin:0}' +
    'table.bw-days tr,table.bw-days tr:hover{background:none !important}' +
    'table.bw-days td{padding:3px 8px 3px 0 !important;border:0 !important;background:none !important;height:auto;white-space:nowrap;vertical-align:middle}' +
    '@container (max-width:520px){table.bw-days .bw-sub{display:none}}' +
    '.bw-bar{width:40%;min-width:80px}.bw-bar i{display:inline-block;height:8px;vertical-align:middle;min-width:0}' +
    '.bw-bar i:first-child{border-radius:2px 0 0 2px}.bw-bar i:last-child{border-radius:0 2px 2px 0}' +
    '.bw-num{font-family:var(--font-mono);text-align:right;font-weight:600}.bw-sub{color:var(--mut);font-size:12px;white-space:normal !important}' +
    '.bw-note{font-size:12px;color:var(--mut);margin:8px 0 0}';
  document.head.appendChild(css);
})();
