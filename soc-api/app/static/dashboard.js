let state = {
  activeOnly: true,
  severity: "",
  srcIp: "",
};
let charts = {
  eventsPerMin: null,
  severity: null,
  topIps: null,
};
function qs(id) { return document.getElementById(id); }

async function fetchData() {
  const params = new URLSearchParams();
  params.set("alerts_limit", "25");
  params.set("events_limit", "25");
  params.set("active_only", String(state.activeOnly));
  if (state.severity) params.set("severity", state.severity);
  if (state.srcIp) params.set("src_ip", state.srcIp);

  const res = await fetch(`/dashboard/data?${params.toString()}`);
  if (!res.ok) throw new Error("Failed to load dashboard data");
  return await res.json();
}

function sevClass(sev) {
  if (sev === "high") return "sev-high";
  if (sev === "medium") return "sev-medium";
  if (sev === "low") return "sev-low";
  return "";
}

function renderKpi(kpi) {
  qs("kpiActiveAlerts").textContent = kpi.active_alerts ?? 0;
  qs("kpiTotalAlerts").textContent = kpi.total_alerts ?? 0;
  qs("kpiEventsHour").textContent = kpi.events_last_hour ?? 0;
  qs("kpiTotalEvents").textContent = kpi.total_events ?? 0;
}

function renderAlerts(alerts) {
  const table = qs("alertsTable");
  table.innerHTML = `
    <div class="row head">
      <div>ID</div><div>Time</div><div>Rule</div><div>Severity</div><div>Host</div><div>Src IP</div><div>User</div><div>Status</div><div>Action</div>
    </div>
  `;

  if (!alerts?.length) {
    table.innerHTML += `<div class="row"><div class="muted" style="grid-column:1/-1">No alerts</div></div>`;
    return;
  }

  for (const a of alerts) {
    const status = a.is_active
      ? `<span class="status active">active</span>`
      : `<span class="status resolved">resolved</span>`;

    const action = a.is_active
      ? `<button class="small" data-resolve="${a.id}">Resolve</button>`
      : `<span class="muted">—</span>`;

    table.innerHTML += `
      <div class="row">
        <div>#${a.id}</div>
        <div class="mono">${a.created_at}</div>
        <div>${a.rule}</div>
        <div class="sev ${sevClass(a.severity)}">${a.severity}</div>
        <div>${a.host ?? ""}</div>
        <div class="mono">${a.src_ip ?? ""}</div>
        <div>${a.user ?? ""}</div>
        <div>${status}</div>
        <div>${action}</div>
      </div>
      <div class="row-detail muted">${a.message}</div>
    `;
  }

  table.querySelectorAll("[data-resolve]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-resolve");
      await fetch(`/alerts/${id}/resolve`, { method: "PATCH" });
      await refresh();
    });
  });
}

function renderEvents(events) {
  const table = qs("eventsTable");
  if (qs("eventsCount")) qs("eventsCount").textContent = `${events?.length ?? 0} shown`;

  table.innerHTML = `
    <div class="row head">
      <div>ID</div><div>Received</div><div>Type</div><div>Host</div><div>Src IP</div><div>User</div>
    </div>
  `;

  if (!events?.length) {
    table.innerHTML += `<div class="row"><div class="muted" style="grid-column:1/-1">No events</div></div>`;
    return;
  }

  for (const e of events) {
    table.innerHTML += `
      <div class="row">
        <div>#${e.id}</div>
        <div class="mono">${e.received_at}</div>
        <div>${e.event_type}</div>
        <div>${e.host}</div>
        <div class="mono">${e.src_ip ?? ""}</div>
        <div>${e.user ?? ""}</div>
      </div>
      <div class="row-detail muted">${e.message}</div>
    `;
  }
}

/* ---------------- CHARTS ---------------- */

function computeStatsFromPayload(payload) {
  const events = payload.events ?? [];
  const alerts = payload.alerts ?? [];

  // --- events_per_min : bucket par minute (sur les events reçus dans la page) ---
  const perMin = new Map(); // key = "YYYY-MM-DDTHH:MM"
  for (const e of events) {
    const d = new Date(e.received_at);
    if (Number.isNaN(d.getTime())) continue;
    const key = d.toISOString().slice(0, 16); // YYYY-MM-DDTHH:MM
    perMin.set(key, (perMin.get(key) ?? 0) + 1);
  }
  const events_per_min = [...perMin.entries()]
    .sort((a,b) => a[0].localeCompare(b[0]))
    .map(([minute, count]) => ({ minute, count }));

  // --- alerts_by_severity ---
  const alerts_by_severity = { low: 0, medium: 0, high: 0 };
  for (const a of alerts) {
    const s = (a.severity ?? "").toLowerCase();
    if (s in alerts_by_severity) alerts_by_severity[s] += 1;
  }

  // --- top_src_ips (sur events) ---
  const ipCount = new Map();
  for (const e of events) {
    const ip = e.src_ip ?? "";
    if (!ip) continue;
    ipCount.set(ip, (ipCount.get(ip) ?? 0) + 1);
  }
  const top_src_ips = [...ipCount.entries()]
    .sort((a,b) => b[1] - a[1])
    .slice(0, 8)
    .map(([ip, count]) => ({ ip, count }));

  return {
    window: "from page payload",
    events_per_min,
    alerts_by_severity,
    top_src_ips
  };
}
function ensureCharts(payload) {
  if (typeof Chart === "undefined") {
    console.warn("Chart.js not loaded (Chart is undefined).");
    return;
  }

  const stats = computeStatsFromPayload(payload);

  // 1) Events per minute
  const c1 = qs("chartEventsPerMin");
  if (c1) {
    const ctx = c1.getContext("2d");
    const labels = stats.events_per_min.map(x => x.minute.slice(11)); // HH:MM
    const values = stats.events_per_min.map(x => x.count);

    if (!charts.eventsPerMin) {
      charts.eventsPerMin = new Chart(ctx, {
        type: "line",
        data: { labels, datasets: [{ label: "Events/min", data: values }] },
        options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true } } }
      });
    } else {
      charts.eventsPerMin.data.labels = labels;
      charts.eventsPerMin.data.datasets[0].data = values;
      charts.eventsPerMin.update();
    }
  }

  // 2) Alerts by severity
  const c2 = qs("chartSeverity");
  if (c2) {
    const ctx = c2.getContext("2d");
    const sevLabels = ["low", "medium", "high"];
    const sevValues = sevLabels.map(s => stats.alerts_by_severity[s] ?? 0);

    if (!charts.severity) {
      charts.severity = new Chart(ctx, {
        type: "bar",
        data: { labels: sevLabels, datasets: [{ label: "Alerts", data: sevValues }] },
        options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true } } }
      });
    } else {
      charts.severity.data.datasets[0].data = sevValues;
      charts.severity.update();
    }
  }

  // 3) Top IPs
  const c3 = qs("chartTopIPs");
  if (c3) {
    const ctx = c3.getContext("2d");
    const labels = stats.top_src_ips.map(x => x.ip);
    const values = stats.top_src_ips.map(x => x.count);

    if (!charts.topIps) {
      charts.topIps = new Chart(ctx, {
        type: "bar",
        data: { labels, datasets: [{ label: "Events", data: values }] },
        options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true } } }
      });
    } else {
      charts.topIps.data.labels = labels;
      charts.topIps.data.datasets[0].data = values;
      charts.topIps.update();
    }
  }

  const win = qs("statsWindow");
  if (win) win.textContent = stats.window;
}

async function refresh() {
  try {
    const data = await fetchData();
    renderKpi(data.kpi);
    renderAlerts(data.alerts);
    renderEvents(data.events);
    ensureCharts(data); // ✅ AJOUT IMPORTANT
  } catch (e) {
    console.error(e);
  }
}

function init() {
  qs("refreshBtn")?.addEventListener("click", refresh);

  qs("applyFilters")?.addEventListener("click", () => {
    state.activeOnly = qs("activeOnly")?.checked ?? true;
    state.severity = qs("severity")?.value ?? "";
    state.srcIp = (qs("srcIp")?.value ?? "").trim();
    refresh();
  });

  refresh();
  setInterval(refresh, 5000);
}

document.addEventListener("DOMContentLoaded", init);
