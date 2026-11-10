/* Shared code for the router console pages (router*.html) and ping.html.
   No build step, no libraries: LC.* helpers + a model built from router.json. */
(function () {
  'use strict';
  var LC = window.LC = {};

  // ---------------------------------------------------------------- basics
  var esc = LC.esc = function (s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  };
  LC.$ = function (id) { return document.getElementById(id); };
  LC.fmtInt = function (n) { return n == null ? '–' : Math.round(n).toLocaleString('en-US'); };

  // Deco speeds: device_list_speed / client_list_speed. Assumed kB/s (unconfirmed).
  LC.UNIT = 'kB/s';
  LC.fmtRate = function (v) {
    if (v == null) return '–';
    if (v >= 10000) return (v / 1000).toFixed(0) + ' MB/s';
    if (v >= 1000) return (v / 1000).toFixed(1) + ' MB/s';
    return Math.round(v) + ' kB/s';
  };
  LC.fmtDur = function (sec) {
    if (sec == null || sec < 0) return '–';
    var d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
    return d ? d + ' d ' + h + ' h' : h ? h + ' h ' + m + ' m' : m + ' m';
  };
  LC.fmtTime = function (d) { return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); };
  LC.ago = function (d) {
    var s = Math.round((Date.now() - d.getTime()) / 1000);
    return s < 60 ? 'just now' : s < 3600 ? Math.round(s / 60) + ' min ago' : Math.round(s / 3600) + ' h ago';
  };
  LC.shortIp = function (ip) { return ip ? '.' + ip.split('.').pop() : 'no IP'; };

  LC.api = function (path, opts) {
    return fetch(path, Object.assign({ cache: 'no-store' }, opts || {})).then(function (r) {
      return r.json().catch(function () { return { ok: false, error: 'HTTP ' + r.status }; }).then(function (j) {
        if (j && j.busy && j.busy.busy) LC.watchBusy(j.busy);
        if (r.status === 503 && j.busy) throw new Error('The router is still applying the last change. Try again in about ' + j.busy.retry_after + ' s.');
        if (!r.ok || j.ok === false) throw new Error(j.error || ('HTTP ' + r.status));
        return j;
      });
    });
  };
  LC.post = function (path, body) {
    return LC.api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
  };
  LC.banner = function (msg) {
    var b = LC.$('banner'); if (!b) return;
    b.textContent = msg || ''; b.style.display = msg ? 'block' : 'none';
  };

  // Deco base64-encodes most free-text names (client name, custom node names, SSIDs,
  // port-forward service names). Preset node names ("garage", "family_room") are plain.
  LC.b64 = function (s) {
    if (!s || s.length < 4 || s.length % 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return null;
    try {
      var bin = atob(s), bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      var out = new TextDecoder('utf-8', { fatal: true }).decode(bytes).trim();
      return /^[^\u0000-\u001f\u007f-\u009f�]+$/.test(out) ? out : null;
    } catch (e) { return null; }
  };
  LC.text = function (s) { var d = LC.b64(s); return d != null ? d : (s || ''); };
  function pretty(s) { s = s.replace(/_/g, ' ').trim(); return s.charAt(0).toUpperCase() + s.slice(1); }
  LC.macColon = function (m) { return (m || '').replace(/-/g, ':').toLowerCase(); };

  // ---------------------------------------------------------------- model
  var BAND = { band2_4: '2.4 GHz', band5: '5 GHz', band5_1: '5 GHz', band5_2: '5 GHz-2', band6: '6 GHz' };
  LC.bandLabel = function (b) { return BAND[b] || b; };
  LC.WEAK_DBM = -70;

  LC.loadRouter = function () {
    return fetch('router.json?t=' + Date.now(), { cache: 'no-store' }).then(function (r) {
      if (r.status === 404) throw new Error('No router snapshot yet (web/router.json). Is lan-router.timer running and router.env set?');
      if (!r.ok) throw new Error('router.json: HTTP ' + r.status);
      return r.json();
    }).then(LC.model);
  };

  LC.model = function (d) {
    function res(name) { var r = (d.reads || {})[name]; return r && r.ok ? r.result : null; }
    var m = { raw: d, res: res, generated: new Date(d.generated), error: d.error || null,
              // source "web": the TMP port refused, so router_collect read the web interface instead
              // (deco_web.py): nodes + clients + WAN + CPU/mem, but no per-client node/signal, no settings
              source: d.source || 'tmp', partial: d.source === 'web',
              // full (TMP) reads only happen on "Refresh now"; web snapshots carry their other sections over
              fullGenerated: d.full_generated ? new Date(d.full_generated) : (d.source === 'web' ? null : new Date(d.generated)),
              fullError: d.full_error || null };
    m.stale = function (name) { var r = (d.reads || {})[name]; return !!(r && r.stale); };

    // nodes
    var speeds = {};
    ((res('device_list_speed') || {}).device_list_speed || []).forEach(function (s) { speeds[s.device_id] = s; });
    var resInfo = ((res('device_resource_info') || {}).device_list || [])[0] || null;
    var nodes = ((res('device_list') || {}).device_list || []).map(function (n) {
      var raw = n.nickname === 'custom' ? (n.custom_nickname || '') : (n.nickname || '');
      var name = raw ? pretty(LC.text(raw)) : '';
      var bands = (n.connection_type || []).filter(function (t) { return t !== 'wired'; });
      var levels = bands.map(function (b) { return Number((n.signal_level || {})[b] || 0); });
      // group_status = mesh membership, which is what the Deco app calls online. inet_status is the node's
      // own internet check and can say "offline" on a node that is serving clients (a just-moved X55 did).
      var online = n.group_status === 'connected' && !!n.ip;
      var sp = speeds[n.device_id] || {};
      return {
        id: n.device_id, mac: LC.macColon(n.mac), raw: n, name: name || (n.role === 'master' ? 'Gateway' : 'Unnamed ' + n.device_model),
        model: n.device_model, hw: n.hardware_ver, fw: (n.software_ver || '').split(' ')[0], ip: n.ip || '',
        master: n.role === 'master', parent: n.parent_device_id === n.device_id ? null : n.parent_device_id,
        online: online, wired: (n.connection_type || []).indexOf('wired') >= 0, wireless: bands.length > 0,
        bands: bands, levels: levels,
        weak: online && bands.length > 0 && Math.min.apply(null, levels) <= 1,
        inetCheck: n.inet_status || '', down: sp.down_speed, up: sp.up_speed, clients: 0, clientIds: []
      };
    });
    var byId = {}; nodes.forEach(function (n) { byId[n.id] = n; });
    nodes.forEach(function (n) {
      if (n.parent && !byId[n.parent]) n.parent = null;
      var depth = 0, p = n.parent, guard = 0;
      while (p && byId[p] && guard++ < 10) { depth++; p = byId[p].parent; }
      n.depth = n.master ? 0 : Math.max(depth, 1);
    });
    // a node sits behind a weak link if it, or any node on its path to the gateway, is weak
    nodes.forEach(function (n) {
      var p = n, guard = 0; n.behindWeak = null;
      while (p && guard++ < 10) { if (p.weak) { n.behindWeak = p; break; } p = byId[p.parent]; }
    });
    m.nodes = nodes; m.nodeById = byId;
    m.master = nodes.filter(function (n) { return n.master; })[0] || null;
    m.resource = resInfo;

    // clients
    var cspeed = {};
    ((res('client_list_speed') || {}).client_list_speed || []).forEach(function (s) { cspeed[LC.macColon(s.mac)] = s; });
    var reserved = {};
    ((res('reservations') || {}).reservation_list || []).forEach(function (r) { reserved[LC.macColon(r.mac)] = r.ip; });
    var blocked = {};
    ((res('access_control_white_list') || {}).client_list || []).concat((res('blocked_list') || {}).client_list || [])
      .forEach(function (c) { blocked[LC.macColon(c.mac)] = true; });
    // Web snapshots map clients to nodes via per-node lists; if that failed, counts are unknown, not 0.
    var linked = ((res('client_list') || {}).client_list || []).some(function (c) { return (c.linked_device_info || {}).device_id; });
    if (m.partial && !linked) nodes.forEach(function (n) { n.clients = null; });
    m.clients = ((res('client_list') || {}).client_list || []).map(function (c) {
      var li = c.linked_device_info || {}, band = (li.connection_type || []).filter(function (t) { return t !== 'wired'; })[0];
      var mac = LC.macColon(c.mac), sp = cspeed[mac] || {};
      var name = LC.text(c.name);
      if (!name || name.toLowerCase() === 'none') name = '';
      var node = byId[li.device_id] || null;
      if (c.online && node && node.clients != null) { node.clients++; }
      return {
        raw: c, mac: mac, macDash: c.mac, name: name, label: name || c.ip || mac, ip: c.ip || '', online: !!c.online,
        wired: c.wire_type === 'wired', band: band || null,
        signal: band ? ((li.signal_strength || {})[band] || null) : null,
        level: band ? ((li.signal_level || {})[band] || null) : null,
        net: c.interface || '', type: c.client_type || 'other', node: node,
        onlineTime: c.online_time, down: sp.down_speed, up: sp.up_speed,
        reservedIp: reserved[mac] || null, blocked: !!blocked[mac]
      };
    });
    m.online = m.clients.filter(function (c) { return c.online; });
    return m;
  };

  // Attention items shared by the overview and the mesh page.
  LC.alerts = function (m) {
    var out = [];
    m.nodes.filter(function (n) { return n.weak; }).forEach(function (n) {
      var behind = m.online.filter(function (c) { return c.node && c.node.behindWeak === n; }).length;
      out.push({ kind: 'warn', icon: 'warn', node: n,
        title: 'Weak backhaul: ' + n.name + ' (' + n.model + ' ' + LC.shortIp(n.ip) + ')',
        text: 'Wireless backhaul at ' + n.bands.map(function (b, i) { return LC.bandLabel(b) + ' ' + n.levels[i] + '/3'; }).join(', ') +
          '. ' + (behind ? behind + ' client' + (behind === 1 ? '' : 's') + ' behind it share' + (behind === 1 ? 's' : '') + ' that link.' : 'No clients behind it right now.') +
          ' Running ethernet to it would fix this.' });
    });
    m.nodes.filter(function (n) { return !n.online; }).forEach(function (n) {
      out.push({ kind: '', icon: 'off', node: n, title: n.name + ' ' + n.model + ' is offline',
        text: 'The mesh still lists it but ' + (n.ip ? 'reports it ' + (n.raw.group_status || 'disconnected') : 'reports no IP') +
          '. Check that it is powered, or remove it from the mesh.' });
    });
    var wan = (m.res('wan_lan_status') || {}).wan;
    if (wan && !(wan.ip_info || {}).ip) out.push({ kind: 'bad', icon: 'off', title: 'No WAN address', text: 'The gateway reports no internet IP address.' });
    var fw = ((m.res('firmware') || {}).fw_list || []).filter(function (f) { return f.need_to_upgrade; });
    if (fw.length) out.push({ kind: '', icon: 'info', title: 'Firmware update available',
      text: fw.map(function (f) { return f.device_model + ' → ' + f.version; }).join(', ') + '. Update from the Deco app.' });
    if (m.resource && m.resource.memory_total && m.resource.memory_usage / m.resource.memory_total > 0.9)
      out.push({ kind: 'warn', icon: 'warn', title: 'Gateway memory above 90%', text: 'A reboot usually clears this.' });
    if (m.error) out.push({ kind: 'bad', icon: 'off', title: 'Last snapshot failed', text: m.error });
    if (m.fullError) out.push({ kind: '', icon: 'info', title: 'Full read refused, showing the web snapshot',
      text: 'The control port refused (' + m.fullError + '). Nodes, clients and gateway load are current from the web interface; ' +
        'settings and client signal are ' + (m.fullGenerated ? 'from the last full read at ' + LC.fmtTime(m.fullGenerated) : 'not available') + '.' });
    return out;
  };

  var ICONS = {
    warn: '<path d="M12 3l9.5 17h-19z"/><path d="M12 10v4M12 17.5v.01"/>',
    off: '<circle cx="12" cy="12" r="9"/><path d="M8 8l8 8"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5v.01"/>',
    ok: '<path d="M5 12.5l4.5 4.5L19 7"/>',
    x: '<path d="M6 6l12 12M18 6L6 18"/>'
  };
  LC.icon = function (name, size) {
    return '<svg width="' + (size || 20) + '" height="' + (size || 20) + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + ICONS[name] + '</svg>';
  };
  LC.renderAlerts = function (box, items, link) {
    box.innerHTML = items.map(function (a) {
      return '<div class="alert ' + a.kind + '">' + LC.icon(a.icon) + '<div><b>' + esc(a.title) + '</b><p>' + esc(a.text) + '</p>' +
        (link && a.node ? '<a href="' + link + '">' + (link.indexOf('mesh') >= 0 ? 'See it on the mesh map' : 'Show its clients') + '</a>' : '') +
        '</div></div>';
    }).join('');
  };

  // ---------------------------------------------------------------- history
  LC.history = function (metric, key, since, points) {
    var q = 'api/history?metric=' + encodeURIComponent(metric) + '&since=' + since + '&points=' + (points || 48) +
      (key != null ? '&key=' + encodeURIComponent(key) : '');
    return LC.api(q).then(function (j) { return j.series || {}; });
  };

  // ---------------------------------------------------------------- drawing
  // Line sparkline. values: [v|null...]; nulls break the line.
  LC.spark = function (values, o) {
    o = o || {};
    var w = o.w || 88, h = o.h || 24, pad = 2;
    var vals = values.filter(function (v) { return v != null; });
    if (!vals.length) return '<svg class="spark" width="' + w + '" height="' + h + '" aria-hidden="true"></svg>';
    var lo = o.min != null ? o.min : Math.min.apply(null, vals), hi = o.max != null ? o.max : Math.max.apply(null, vals);
    if (hi - lo < (o.minSpan || 1e-9)) { var mid = (hi + lo) / 2, s = (o.minSpan || 1) / 2; lo = mid - s; hi = mid + s; }
    var n = values.length, step = n > 1 ? (w - 2 * pad) / (n - 1) : 0, segs = [], cur = [];
    values.forEach(function (v, i) {
      if (v == null) { if (cur.length) segs.push(cur); cur = []; return; }
      var y = h - pad - (Math.min(Math.max(v, lo), hi) - lo) / (hi - lo) * (h - 2 * pad);
      cur.push((pad + i * step).toFixed(1) + ',' + y.toFixed(1));
    });
    if (cur.length) segs.push(cur);
    return '<svg class="spark" width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '" aria-hidden="true">' +
      segs.map(function (sg) {
        return sg.length === 1 ? '<circle cx="' + sg[0].split(',')[0] + '" cy="' + sg[0].split(',')[1] + '" r="1.5" fill="' + o.color + '"/>'
          : '<polyline points="' + sg.join(' ') + '" fill="none" stroke="' + o.color + '" stroke-width="2" stroke-linejoin="round"/>';
      }).join('') + '</svg>';
  };

  // Bar sparkline for ping rounds: one bar per round, a faint full-height band where there was no reply.
  LC.barSpark = function (series, o) {
    o = o || {};
    var w = o.w || 160, h = o.h || 24, n = Math.max(series.length, 1), bw = w / n;
    var vals = series.filter(function (v) { return v != null; }), top = Math.max(50, Math.max.apply(null, vals.concat([0])));
    return '<svg class="spark" width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none" aria-hidden="true">' +
      series.map(function (v, i) {
        var x = (i * bw).toFixed(2), ww = Math.max(bw - (bw > 3 ? 0.5 : 0), 0.5).toFixed(2);
        if (v == null) return '<rect x="' + x + '" y="0" width="' + ww + '" height="' + h + '" fill="var(--bad)" opacity=".35"/>';
        var bh = Math.max(1, h * v / top);
        return '<rect x="' + x + '" y="' + (h - bh).toFixed(2) + '" width="' + ww + '" height="' + bh.toFixed(2) + '" fill="' + LC.latColor(v) + '"/>';
      }).join('') + '</svg>';
  };
  LC.latColor = function (v) { return v == null ? 'var(--bad)' : v < 50 ? 'var(--ok)' : v < 150 ? 'var(--warn)' : 'var(--bad)'; };

  // Two-series area/line chart drawn at the element's real pixel width (so text stays crisp).
  // series: [{points:[[ts,v]...], cls:'down'|'up', fill:bool}], fmt: value -> label
  LC.chart = function (svg, series, o) {
    o = o || {};
    var W = Math.max(280, svg.clientWidth || svg.parentNode.clientWidth || 600), H = o.h || 240;
    var L = 56, R = 8, T = 10, B = 24;
    var all = []; series.forEach(function (s) { s.points.forEach(function (p) { all.push(p); }); });
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    svg.setAttribute('height', H);
    if (!all.length) { svg.innerHTML = ''; return false; }
    var t0 = o.t0 != null ? o.t0 : Math.min.apply(null, all.map(function (p) { return p[0]; }));
    var t1 = o.t1 != null ? o.t1 : Math.max.apply(null, all.map(function (p) { return p[0]; }));
    if (t1 <= t0) t1 = t0 + 1;
    var vmax = Math.max.apply(null, all.map(function (p) { return p[1]; }).concat([o.minMax || 1]));
    var nice = niceMax(vmax);
    function x(t) { return L + (t - t0) / (t1 - t0) * (W - L - R); }
    function y(v) { return T + (1 - v / nice) * (H - T - B); }
    var out = '';
    for (var i = 0; i <= 4; i++) {
      var gv = nice * i / 4, gy = y(gv).toFixed(1);
      out += '<line class="' + (i ? 'grid' : 'axis') + '" x1="' + L + '" x2="' + (W - R) + '" y1="' + gy + '" y2="' + gy + '"/>' +
        '<text x="' + (L - 8) + '" y="' + (Number(gy) + 4) + '" text-anchor="end">' + esc((o.fmt || String)(gv)) + '</text>';
    }
    var ticks = o.ticks || 6;
    for (var k = 0; k <= ticks; k++) {
      var tt = t0 + (t1 - t0) * k / ticks;
      out += '<text x="' + x(tt).toFixed(1) + '" y="' + (H - 6) + '" text-anchor="' + (k === 0 ? 'start' : k === ticks ? 'end' : 'middle') + '">' +
        esc(tickLabel(tt, t1 - t0)) + '</text>';
    }
    series.forEach(function (s) {
      if (!s.points.length) return;
      var gap = o.gap || Infinity, segs = [[]];
      s.points.forEach(function (p, j) {
        if (j && p[0] - s.points[j - 1][0] > gap) segs.push([]);
        segs[segs.length - 1].push(p);
      });
      segs.forEach(function (sg) {
        var d = sg.map(function (p, j) { return (j ? 'L' : 'M') + x(p[0]).toFixed(1) + ' ' + y(p[1]).toFixed(1); }).join(' ');
        if (s.fill && sg.length > 1)
          out += '<path class="' + s.cls + 'fill" d="' + d + ' L' + x(sg[sg.length - 1][0]).toFixed(1) + ' ' + y(0) + ' L' + x(sg[0][0]).toFixed(1) + ' ' + y(0) + ' Z"/>';
        out += sg.length > 1 ? '<path class="' + s.cls + '" d="' + d + '"/>'
          : '<circle cx="' + x(sg[0][0]).toFixed(1) + '" cy="' + y(sg[0][1]).toFixed(1) + '" r="2.5" class="' + s.cls + '"/>';
      });
    });
    svg.innerHTML = out;
    return true;
  };
  function niceMax(v) {
    var p = Math.pow(10, Math.floor(Math.log10(v))), f = v / p;
    return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * p;
  }
  function tickLabel(ts, span) {
    var d = new Date(ts * 1000);
    if (span > 3 * 86400) return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  // ---------------------------------------------------------------- chrome
  var LOGO = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M12 7.5v4M12 11.5l-5.5 5.5M12 11.5l5.5 5.5"/></svg>';
  var SECTIONS = [['devices', 'index.html', 'Devices'], ['router', 'router.html', 'Router'], ['ping', 'ping.html', 'Ping'], ['logs', 'logs.html', 'Logs']];
  var ROUTER_PAGES = [['overview', 'router.html', 'Overview'], ['mesh', 'router-mesh.html', 'Mesh'],
                      ['clients', 'router-clients.html', 'Clients'], ['settings', 'router-settings.html', 'Settings']];

  LC.topbar = function (section, sideHtml) {
    return '<div class="tb-in"><a class="tb-brand" href="index.html">' + LOGO + '<span>LAN Console</span></a>' +
      '<nav aria-label="Sections">' + SECTIONS.map(function (s) {
        return '<a href="' + s[1] + '"' + (s[0] === section ? ' aria-current="page"' : '') + '>' + s[2] + '</a>';
      }).join('') + '</nav><div class="tb-side" id="tbside">' + (sideHtml || '') + '</div></div>';
  };

  // Router pages: top bar with snapshot age + "Refresh now", and the Overview/Mesh/Clients/Settings tabs.
  // onData(model) is called on first load, after "Refresh now", and on the 60 s background check.
  LC.routerPage = function (page, title, onData) {
    var top = document.createElement('header'); top.className = 'topbar';
    top.innerHTML = LC.topbar('router', '<span id="snapage" aria-live="polite">Loading…</span>' +
      '<button type="button" id="refresh" title="Full read over the router\'s control port (settings, signal, speeds). Runs hourly by itself; the 5-minute snapshots use the web interface.">Refresh now</button>');
    document.body.insertBefore(top, document.body.firstChild);
    LC.$('pagehead').innerHTML = '<h1>' + esc(title) + '</h1><nav class="subnav" aria-label="Router pages">' +
      ROUTER_PAGES.map(function (p) { return '<a href="' + p[1] + '"' + (p[0] === page ? ' aria-current="page"' : '') + '>' + p[2] + '</a>'; }).join('') + '</nav>';

    var last = null;
    // Pages without their own alert box (Clients, Settings) still need to say the snapshot is partial.
    function showPartial(m) {
      var box = LC.$('partialnote');
      if (!box) {
        if (LC.$('alerts')) return;
        box = document.createElement('section'); box.id = 'partialnote'; box.className = 'alerts';
        LC.$('pagehead').insertAdjacentElement('afterend', box);
      }
      LC.renderAlerts(box, LC.alerts(m).filter(function (a) { return a.icon === 'info' || a.kind === 'bad'; }), null);
    }
    function stamp() {
      if (!last) return;
      var full = last.fullGenerated;
      LC.$('snapage').textContent = 'Live ' + LC.fmtTime(last.generated) + ' (' + LC.ago(last.generated) + ')' +
        ' · full read ' + (full ? LC.fmtTime(full) + (Date.now() - full > 3600e3 ? ' (' + LC.ago(full) + ')' : '') : 'never');
    }
    function load(force) {
      return LC.loadRouter().then(function (m) {
        LC.banner('');
        if (force || !last || m.raw.generated !== last.raw.generated) { last = m; onData(m); showPartial(m); }
        stamp();
      }).catch(function (e) { LC.banner(e.message); LC.$('snapage').textContent = 'No snapshot'; });
    }
    LC.$('refresh').addEventListener('click', function () {
      var b = this; b.disabled = true; b.textContent = 'Reading router…';
      LC.post('api/refresh').then(function (j) {
        if (j.source === 'web') LC.banner('Full read refused (' + (j.full_error || 'control port unavailable') + '). Showing the web snapshot instead.');
        return load(true).then(function () { if (j.source === 'web') LC.banner('Full read refused (' + (j.full_error || 'control port unavailable') + '). Showing the web snapshot instead.'); });
      })
        .catch(function (e) { LC.banner('Refresh failed: ' + e.message); })
        .then(function () { b.disabled = false; b.textContent = 'Refresh now'; });
    });
    fetch('api/busy', { cache: 'no-store' }).then(function (r) { return r.json(); }).then(LC.watchBusy).catch(function () {});
    document.addEventListener('lc:router-ready', function (e) {
      var since = (e.detail.since || 0) * 1000, tries = 0;
      (function wait() {
        load(false).then(function () {
          if (last && last.generated.getTime() > since) { LC.busyDone(); return; }
          if (++tries < 12) setTimeout(wait, 5000); else LC.busyDone();
        });
      })();
    });
    setInterval(function () { if (!document.hidden) load(false); }, 60000);
    setInterval(stamp, 30000);
    return load(true);
  };

  LC.simpleTopbar = function (section) {
    var top = document.createElement('header'); top.className = 'topbar';
    top.innerHTML = LC.topbar(section, '');
    document.body.insertBefore(top, document.body.firstChild);
  };

  LC.qs = function (k) { return new URLSearchParams(location.search).get(k); };

  // ---------------------------------------------------------------- post-write lock
  // After a write the router closes its control port for ~60-90 s (router_busy.py on the server).
  // While that lasts: a bar under the top bar, and every control that talks to the router is inert.
  LC.BUSY_SEL = '#refresh, .toggle, .review [data-a=apply], [data-act], [data-live], [data-remove], [data-addgo], [data-review]';
  var busyTimer = null, busyBar = null, busySince = null;
  LC.isBusy = function () { return document.body.classList.contains('router-busy'); };
  document.addEventListener('click', function (e) {
    if (LC.isBusy() && e.target.closest && e.target.closest(LC.BUSY_SEL)) { e.preventDefault(); e.stopImmediatePropagation(); }
  }, true);
  function bar() {
    if (busyBar) return busyBar;
    busyBar = document.createElement('div'); busyBar.className = 'busybar'; busyBar.setAttribute('role', 'status');
    busyBar.innerHTML = '<div class="bb-in"><span class="bb-t"></span><span class="bb-s"></span></div><div class="bb-track"><div class="bb-fill"></div></div>';
    var top = document.querySelector('header.topbar');
    if (top) top.insertAdjacentElement('afterend', busyBar); else document.body.insertBefore(busyBar, document.body.firstChild);
    return busyBar;
  }
  function paint(st) {
    var b = bar(), el = st.elapsed || 0, left = Math.round((st.expected || 90) - el);
    b.hidden = false; b.classList.remove('done');
    b.querySelector('.bb-t').textContent = st.phase === 'restarting'
      ? 'Router is restarting its control service after the change. Reads and changes are paused.'
      : 'Router is applying the change' + (st.write ? ' (' + st.write + ')' : '') + '…';
    b.querySelector('.bb-s').textContent = left > 5 ? 'about ' + left + ' s left' : left > -20 ? 'almost done' : 'taking longer than usual';
    b.querySelector('.bb-fill').style.width = (100 * Math.min(0.97, el / (st.expected || 90))).toFixed(1) + '%';
    Array.prototype.forEach.call(document.querySelectorAll(LC.BUSY_SEL), function (x) { x.setAttribute('aria-disabled', 'true'); });
  }
  LC.watchBusy = function (st) {
    if (!st || !st.busy) return;
    if (!LC.isBusy()) busySince = st.since;
    document.body.classList.add('router-busy');
    paint(st);
    clearTimeout(busyTimer);
    busyTimer = setTimeout(function poll() {
      fetch('api/busy', { cache: 'no-store' }).then(function (r) { return r.json(); }).then(function (s2) {
        if (s2.busy) { paint(s2); busyTimer = setTimeout(poll, 2000); return; }
        document.body.classList.remove('router-busy');
        Array.prototype.forEach.call(document.querySelectorAll('[aria-disabled=true]'), function (x) { x.removeAttribute('aria-disabled'); });
        var b = bar(); b.classList.add('done');
        b.querySelector('.bb-t').textContent = 'Router is back' + (s2.last ? ' after ' + Math.round(s2.last.seconds) + ' s' : '') + '. Updating the snapshot…';
        b.querySelector('.bb-s').textContent = ''; b.querySelector('.bb-fill').style.width = '100%';
        document.dispatchEvent(new CustomEvent('lc:router-ready', { detail: { since: busySince } }));
      }).catch(function () { busyTimer = setTimeout(poll, 4000); });
    }, 2000);
  };
  LC.busyDone = function () { if (busyBar) busyBar.hidden = true; };

  // ---------------------------------------------------------------- write review
  // Every router write goes through this: show what changes, say how proven the opcode is,
  // demand a tick for anything not verified or not low-risk, POST, then judge the result by
  // the read-back (`after`), never by the router's ACK.
  LC.TIER = {
    verified: ['ok', 'verified', 'Proven on this router: written, then read back and confirmed.'],
    upstream: ['', 'tested upstream', 'Seen working in Deco app captures, but not yet tried on this router. After applying, the page reads the setting back and shows what the router actually reports.'],
    inferred: ['warn', 'unverified', 'Guessed from the opcode numbering only. It may do nothing, or something other than intended. Check the parameters below before sending.'],
    noop: ['bad', 'tested: no effect', 'The router accepts this write but changes nothing (likely needs a HomeShield subscription).']
  };
  LC.RISK = { medium: ['warn', 'medium risk'], high: ['bad', 'high risk · WAN'] };
  LC.tierBadge = function (tier) { var t = LC.TIER[tier] || LC.TIER.inferred; return '<span class="badge ' + t[0] + '">' + t[1] + '</span>'; };
  LC.riskBadge = function (risk) { var r = LC.RISK[risk]; return r ? '<span class="badge ' + r[0] + '">' + r[1] + '</span>' : ''; };
  LC.same = function (a, b) { return JSON.stringify(a) === JSON.stringify(b); };
  function show(v) { return v === undefined ? '–' : typeof v === 'string' ? v : JSON.stringify(v); }

  // o: {box, title, write, tier, risk, diff:[[field, now, new]], params, editable, verify(after, params) -> {ok, text},
  //     onDone(after, verdict), onCancel()}
  LC.review = function (o) {
    var t = LC.TIER[o.tier] || LC.TIER.inferred, needTick = o.tier !== 'verified' || (o.risk && o.risk !== 'low');
    var editable = o.editable != null ? o.editable : o.tier === 'inferred';
    var box = o.box;
    box.innerHTML = '<div class="rv-k">Review change</div><h2 class="rv-h">' + esc(o.title) + '</h2>' +
      '<div class="rv-badges">' + LC.tierBadge(o.tier) + ' ' + LC.riskBadge(o.risk) + ' <span class="mono mut">' + esc(o.write) + '</span></div>' +
      (o.diff && o.diff.length ? '<div class="rv-grid"><span class="mut small">Field</span><span class="mut small">Now</span><span class="mut small">New</span>' +
        o.diff.map(function (d) {
          return '<span class="mono">' + esc(d[0]) + '</span><span class="mono">' + esc(show(d[1])) + '</span><span class="mono rv-new">' + esc(show(d[2])) + '</span>';
        }).join('') + '</div>' : '') +
      '<div class="rv-note">' + esc(t[2]) + (o.risk === 'high' ? ' Changing this can drop the internet connection for a minute.' : '') + '</div>' +
      '<details class="rv-params"' + (editable ? ' open' : '') + '><summary>Parameters sent</summary>' +
      (editable ? '<label class="sr-only" for="rv-json">Parameters (JSON)</label><textarea id="rv-json" rows="6"></textarea>'
                : '<pre class="mono" id="rv-pre"></pre>') + '</details>' +
      (needTick ? '<label class="check"><input type="checkbox" id="rv-tick"> ' +
        (o.tier === 'verified' ? 'I understand this setting can affect other devices' : 'I understand this hasn\'t been proven on this router') + '</label>' : '') +
      '<div class="rv-err" role="alert"></div>' +
      '<div class="rv-btns"><button type="button" class="btn" data-a="cancel">Cancel</button><button type="button" class="btn primary" data-a="apply">Apply</button></div>';
    var json = JSON.stringify(o.params, null, 1);
    if (editable) box.querySelector('#rv-json').value = json; else box.querySelector('#rv-pre').textContent = json;
    var apply = box.querySelector('[data-a=apply]'), tick = box.querySelector('#rv-tick'), err = box.querySelector('.rv-err');
    if (tick) { apply.disabled = true; tick.addEventListener('change', function () { apply.disabled = !tick.checked; }); }
    box.querySelector('[data-a=cancel]').addEventListener('click', function () { box.innerHTML = ''; if (o.onCancel) o.onCancel(); });
    apply.addEventListener('click', function () {
      var params = o.params;
      if (editable) {
        try { params = JSON.parse(box.querySelector('#rv-json').value); } catch (e) { err.textContent = 'Parameters are not valid JSON: ' + e.message; return; }
      }
      apply.disabled = true; apply.textContent = 'Applying…'; err.textContent = '';
      LC.post('api/write', { name: o.write, params: params, allow_unverified: o.tier !== 'verified' }).then(function (res) {
        var v = o.verify ? o.verify(res.after, params) : { ok: null, text: 'Router now reports: ' + JSON.stringify(res.after) };
        box.innerHTML = LC.resultHtml(o.title, v, res.after);
        if (o.onDone) o.onDone(res.after, v);
      }).catch(function (e) {
        err.textContent = 'Write failed: ' + e.message;
        apply.disabled = false; apply.textContent = 'Apply';
      });
    });
    var first = box.querySelector('#rv-tick, #rv-json, [data-a=apply]'); if (first && !o.noFocus) first.focus();
  };
  LC.resultHtml = function (title, v, after) {
    var cls = v.ok === true ? 'ok' : v.ok === false ? 'bad' : '';
    var head = v.ok === true ? title + ' applied' : v.ok === false ? 'Accepted but no change' : 'Sent: ' + title;
    return '<div class="rv-result ' + cls + '"><div class="rv-rh">' + LC.icon(v.ok === false ? 'x' : v.ok ? 'ok' : 'info', 18) + esc(head) + '</div>' +
      '<p>' + esc(v.text) + '</p>' + (after != null ? '<details><summary>Read-back</summary><pre class="mono">' + esc(JSON.stringify(after, null, 1)) + '</pre></details>' : '') + '</div>';
  };
  // Generic verdict for a whole-object write: every requested field must read back equal.
  LC.verifyFields = function (fields) {
    return function (after, params) {
      if (!after) return { ok: null, text: 'No read-back available for this write.' };
      var bad = fields.filter(function (f) { return !LC.same(after[f], params[f]); });
      if (!bad.length) return { ok: true, text: 'Router now reports ' + fields.map(function (f) { return f + ': ' + show(after[f]); }).join(', ') + ', which matches what you asked for.' };
      return { ok: false, text: 'The router said OK, but reading it back shows ' + bad.map(function (f) {
        return f + ': ' + show(after[f]) + ' (asked for ' + show(params[f]) + ')'; }).join(', ') + '.' };
    };
  };
})();
