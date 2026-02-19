let state = {
  activeOnly: true,
  severity: "",
  srcIp: "",
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
  qs("kpiActiveAlerts").textContent = kpi.active_alerts;
  qs("kpiTotalAlerts").textContent = kpi.total_alerts;
  qs("kpiEventsHour").textContent = kpi.events_last_hour;
  qs("kpiTotalEvents").textContent = kpi.total_events;
}

function renderAlerts(alerts) {
  const table = qs("alertsTable");
  table.innerHTML = `
    <div class="row head">
      <div>ID</div><div>Time</div><div>Rule</div><div>Severity</div><div>Host</div><div>Src IP</div><div>User</div><div>Status</div><div>Action</div>
    </div>
  `;

  if (!alerts.length) {
    table.innerHTML += `<div class="row"><div class="muted" style="grid-column:1/-1">No alerts</div></div>`;
    return;
  }

  for (const a of alerts) {
    const status = a.is_active ? `<span class="status active">active</span>` : `<span class="status resolved">resolved</span>`;
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

  // bind resolve buttons
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
  qs("eventsCount").textContent = `${events.length} shown`;

  table.innerHTML = `
    <div class="row head">
      <div>ID</div><div>Received</div><div>Type</div><div>Host</div><div>Src IP</div><div>User</div>
    </div>
  `;

  if (!events.length) {
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

async function refresh() {
  try {
    const data = await fetchData();
    renderKpi(data.kpi);
    renderAlerts(data.alerts);
    renderEvents(data.events);
  } catch (e) {
    console.error(e);
  }
}

function init() {
  qs("refreshBtn").addEventListener("click", refresh);

  qs("applyFilters").addEventListener("click", () => {
    state.activeOnly = qs("activeOnly").checked;
    state.severity = qs("severity").value;
    state.srcIp = qs("srcIp").value.trim();
    refresh();
  });

  // auto refresh
  refresh();
  setInterval(refresh, 5000);
}

init();

