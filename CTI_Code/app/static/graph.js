// app/static/graph.js

const svg = d3.select("#graph");
let width = svg.node().clientWidth;
let height = svg.node().clientHeight;

window.addEventListener("resize", () => {
  width = svg.node().clientWidth;
  height = svg.node().clientHeight;
});

// ---------- helpers: styling ----------
function labelOf(n) {
  if (n.entity_type) return n.entity_type;
  return (n.labels || []).join(":");
}

function radiusFor(n) {
  const labs = new Set(n.labels || []);
  if (labs.has("Host")) return 14;
  if (labs.has("Vulnerability")) return 12;
  if (labs.has("AttackPattern")) return 12;
  if (labs.has("Malware")) return 12;
  if (labs.has("IntrusionSet")) return 12;
  if (labs.has("NVT")) return 11;
  return 10;
}

function nodeColor(n) {
  const labs = new Set(n.labels || []);
  if (labs.has("Host")) return "#1d3557";
  if (labs.has("Vulnerability")) return "#e63946";
  if (labs.has("AttackPattern")) return "#f4a261";
  if (labs.has("Malware")) return "#2a9d8f";
  if (labs.has("IntrusionSet")) return "#6a4c93";
  if (labs.has("NVT")) return "#457b9d";
  return "#555";
}

function edgeColor(type) {
  switch (type) {
    case "USES": return "#e63946";
    case "TARGETS": return "#f4a261";
    case "IS": return "#2a9d8f";
    case "REFERS_TO": return "#457b9d";
    case "VULNERABLE_TO": return "#6a4c93";
    case "HAS_NVT": return "#999";
    default: return "#bbb";
  }
}

// ---------- UI helpers ----------
function ensureLabelToggle() {
  if (document.getElementById("toggleLabels")) return;

  const header = document.querySelector("header");
  if (!header) return;

  const wrap = document.createElement("label");
  wrap.style.marginLeft = "8px";
  wrap.style.fontSize = "12px";
  wrap.style.opacity = "0.85";
  wrap.innerHTML = `<input id="toggleLabels" type="checkbox" checked style="vertical-align: middle; margin-right: 6px;">labels`;
  header.appendChild(wrap);
}

function ensureLegend() {
  if (document.getElementById("legend")) return;

  const legend = document.createElement("div");
  legend.id = "legend";
  legend.style.position = "absolute";
  legend.style.right = "12px";
  legend.style.bottom = "12px";
  legend.style.background = "rgba(255,255,255,0.92)";
  legend.style.border = "1px solid rgba(0,0,0,0.15)";
  legend.style.borderRadius = "10px";
  legend.style.padding = "10px 12px";
  legend.style.fontSize = "12px";
  legend.style.boxShadow = "0 2px 10px rgba(0,0,0,0.1)";
  legend.style.maxWidth = "340px";

  const rows = [
    ["USES", edgeColor("USES")],
    ["TARGETS", edgeColor("TARGETS")],
    ["IS", edgeColor("IS")],
    ["REFERS_TO", edgeColor("REFERS_TO")],
    ["VULNERABLE_TO", edgeColor("VULNERABLE_TO")],
    ["HAS_NVT", edgeColor("HAS_NVT")],
  ];

  legend.innerHTML = `
    <div style="font-weight:600; margin-bottom:8px;">Edges</div>
    ${rows.map(([t, c]) => `
      <div style="display:flex; align-items:center; gap:8px; margin:4px 0;">
        <span style="display:inline-block; width:18px; height:3px; background:${c};"></span>
        <span>${t}</span>
      </div>
    `).join("")}
    <div style="margin-top:8px; opacity:.85; line-height:1.35;">
      <div><b>Drag</b>: uzel se “připíchne” (zůstane na místě)</div>
      <div><b>Dvojklik</b>: unpin (vrátí se do simulace)</div>
      <div><b>P</b>: pin/unpin ALL</div>
      <div><b>Klik</b>: detail panel (Neo4j)</div>
      <div><b>SHIFT+klik</b>: drill-down (načte subgraph)</div>
    </div>
  `;
  document.body.appendChild(legend);
}

// ---------- Context panel (sidebar) ----------
function ensureCtxPanel() {
  if (document.getElementById("ctx")) return;

  const panel = document.createElement("div");
  panel.id = "ctx";
  panel.style.position = "fixed";
  panel.style.top = "70px";
  panel.style.right = "12px";
  panel.style.width = "380px";
  panel.style.maxHeight = "calc(100vh - 90px)";
  panel.style.overflow = "auto";
  panel.style.background = "rgba(255,255,255,0.97)";
  panel.style.border = "1px solid rgba(0,0,0,0.15)";
  panel.style.borderRadius = "14px";
  panel.style.padding = "12px 12px 10px";
  panel.style.boxShadow = "0 10px 30px rgba(0,0,0,0.15)";
  panel.style.display = "none";
  panel.style.zIndex = "9999";

  panel.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center; gap:8px;">
      <div id="ctxTitle" style="font-weight:700; font-size:14px;">Node</div>
      <button id="ctxClose" style="border:1px solid #0002; background:#fff; border-radius:10px; padding:4px 10px; cursor:pointer;">×</button>
    </div>
    <div id="ctxMeta" style="margin-top:6px; font-size:12px; opacity:.75;"></div>
    <hr style="border:none; border-top:1px solid #0001; margin:10px 0;">
    <div style="font-weight:600; font-size:13px; margin-bottom:6px;">Properties</div>
    <pre id="ctxProps" style="white-space:pre-wrap; font-size:12px; background:#f6f6f6; padding:10px; border-radius:12px; margin:0;"></pre>
    <div style="font-weight:600; font-size:13px; margin:10px 0 6px;">Neighbors</div>
    <div id="ctxNeigh" style="font-size:12px;"></div>
  `;

  document.body.appendChild(panel);

  document.getElementById("ctxClose").onclick = () => {
    panel.style.display = "none";
  };
}

function showCtxPanel(node) {
  ensureCtxPanel();
  const panel = document.getElementById("ctx");
  panel.style.display = "block";

  document.getElementById("ctxTitle").textContent = node.title || node.id;
  document.getElementById("ctxMeta").textContent =
    `${(node.labels || []).join(", ")}${node.entity_type ? " | " + node.entity_type : ""} | id=${node.id}`;

  document.getElementById("ctxProps").textContent = "Loading...";
  document.getElementById("ctxNeigh").innerHTML = "Loading...";
}

function renderCtxDetails(d) {
  document.getElementById("ctxTitle").textContent = d.title || d.id;
  document.getElementById("ctxMeta").textContent =
    `${(d.labels || []).join(", ")}${d.entity_type ? " | " + d.entity_type : ""} | id=${d.id}`;

  document.getElementById("ctxProps").textContent = JSON.stringify(d.props || {}, null, 2);

  const byRel = new Map();
  (d.neighbors || []).forEach(n => {
    const key = `${n.dir} ${n.rel}`;
    if (!byRel.has(key)) byRel.set(key, []);
    byRel.get(key).push(n);
  });

  const container = document.getElementById("ctxNeigh");
  container.innerHTML = "";

  for (const [k, arr] of byRel.entries()) {
    const wrap = document.createElement("div");
    wrap.style.marginBottom = "10px";

    const h = document.createElement("div");
    h.style.fontWeight = "700";
    h.style.marginBottom = "4px";
    h.textContent = `${k} (${arr.length})`;
    wrap.appendChild(h);

    arr.slice(0, 40).forEach(x => {
      const line = document.createElement("div");
      line.style.padding = "2px 0";
      line.style.cursor = "pointer";
      line.textContent = `• ${x.other_title} [${(x.other_labels || []).join(", ")}]`;
      line.onclick = () => loadGraph(x.other_id);
      wrap.appendChild(line);
    });

    container.appendChild(wrap);
  }
}

// ---------- API ----------
async function apiJson(url) {
  const res = await fetch(url);
  if (!res.ok) {
    const txt = await res.text();
    console.error("API error:", res.status, txt);
    alert(`API error ${res.status}:\n${txt.slice(0, 300)}`);
    return null;
  }
  return await res.json();
}

async function doSearch() {
  const q = document.getElementById("q").value.trim();
  if (q.length < 2) return;
  const data = await apiJson(`/api/search?q=${encodeURIComponent(q)}&limit=30`);
  if (!data) return;
  renderResults(data.results || []);
}

function renderResults(results) {
  const el = document.getElementById("results");
  el.innerHTML = "";

  results.forEach(r => {
    const div = document.createElement("div");
    div.className = "item";
    div.textContent = `${r.title}  [${(r.labels || []).join(", ")}]  score=${Number(r.score).toFixed(2)}`;
    div.onclick = () => loadGraph(r.id);
    el.appendChild(div);
  });
}

async function loadGraph(node_id) {
  const radius = parseInt(document.getElementById("radius").value || "2", 10);
  const data = await apiJson(`/api/graph?node_id=${encodeURIComponent(node_id)}&radius=${radius}&max_nodes=400`);
  if (!data) return;
  draw(data.nodes || [], data.edges || []);
}

async function loadNodeDetails(node) {
  showCtxPanel(node);
  const details = await apiJson(`/api/node?id=${encodeURIComponent(node.id)}&neigh_limit=120`);
  if (details) renderCtxDetails(details);
}

// ---------- draw ----------
let currentSim = null;
let currentNodes = [];

function draw(nodes, edges) {
  ensureLabelToggle();
  ensureLegend();
  ensureCtxPanel();

  currentNodes = nodes;

  svg.selectAll("*").remove();

  const g = svg.append("g");
  svg.call(d3.zoom().on("zoom", (event) => g.attr("transform", event.transform)));

  // defs: šipky pro edge typy
  const edgeTypes = Array.from(new Set((edges || []).map(e => e.type))).sort();
  const defs = svg.append("defs");

  defs.selectAll("marker")
    .data(edgeTypes)
    .enter()
    .append("marker")
    .attr("id", d => `arrow-${d}`)
    .attr("viewBox", "0 -5 10 10")
    .attr("refX", 18)
    .attr("refY", 0)
    .attr("markerWidth", 6)
    .attr("markerHeight", 6)
    .attr("orient", "auto")
    .append("path")
    .attr("d", "M0,-5L10,0L0,5")
    .attr("fill", d => edgeColor(d));

  const nodeById = new Map(nodes.map(n => [n.id, n]));
  const links = (edges || [])
    .filter(e => nodeById.has(e.source) && nodeById.has(e.target))
    .map(e => ({ ...e }));

  // Force simulation: víc místa pro labely, méně chumlu
  const sim = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id(d => d.id).distance(105))
    .force("charge", d3.forceManyBody().strength(-170))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("collide", d3.forceCollide().radius(d => radiusFor(d) + 14))
    .force("x", d3.forceX(width / 2).strength(0.03))
    .force("y", d3.forceY(height / 2).strength(0.03));

  currentSim = sim;

  // edges
  const link = g.selectAll("line")
    .data(links)
    .enter()
    .append("line")
    .attr("stroke", d => edgeColor(d.type))
    .attr("stroke-width", 1.8)
    .attr("opacity", 0.85)
    .attr("marker-end", d => `url(#arrow-${d.type})`);

  link.append("title").text(d => d.type);

  // drag behavior: po puštění uzel zůstane (PIN)
  function dragstarted(event, d) {
    if (!event.active) sim.alphaTarget(0.2).restart();
    d.fx = d.x;
    d.fy = d.y;
  }
  function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
  }
  function dragended(event, d) {
    if (!event.active) sim.alphaTarget(0);
    d.pinned = true; // fx/fy zůstávají nastavené
  }

  // nodes
  const node = g.selectAll("circle")
    .data(nodes)
    .enter()
    .append("circle")
    .attr("r", d => radiusFor(d))
    .attr("fill", d => nodeColor(d))
    .attr("stroke", "rgba(0,0,0,0.25)")
    .attr("stroke-width", 1)
    .on("click", async (event, d) => {
      // SHIFT+klik = drill-down, normální klik = panel s detaily
      if (event.shiftKey) {
        await loadGraph(d.id);
      } else {
        await loadNodeDetails(d);
      }
    })
    .on("dblclick", (_, d) => { // UNPIN
      d.fx = null;
      d.fy = null;
      d.pinned = false;
      sim.alpha(0.5).restart();
    })
    .call(d3.drag().on("start", dragstarted).on("drag", dragged).on("end", dragended));

  node.append("title").text(d => `${d.title}\n${labelOf(d)}\n${d.id}`);

  // labels toggle
  const labelsOn = () => document.getElementById("toggleLabels")?.checked ?? true;

  // halo pro čitelnost
  const labelGroup = g.append("g");

  const textHalo = labelGroup.selectAll("text.halo")
    .data(nodes)
    .enter()
    .append("text")
    .attr("class", "halo")
    .text(d => (d.title ? String(d.title).slice(0, 44) : d.id))
    .attr("font-size", 11)
    .attr("dx", 14)
    .attr("dy", 4)
    .attr("pointer-events", "none")
    .attr("stroke", "white")
    .attr("stroke-width", 3.5)
    .attr("stroke-linejoin", "round")
    .attr("opacity", labelsOn() ? 0.95 : 0.0);

  const text = labelGroup.selectAll("text.label")
    .data(nodes)
    .enter()
    .append("text")
    .attr("class", "label")
    .text(d => (d.title ? String(d.title).slice(0, 44) : d.id))
    .attr("font-size", 11)
    .attr("dx", 14)
    .attr("dy", 4)
    .attr("pointer-events", "none")
    .attr("fill", "#111")
    .attr("opacity", labelsOn() ? 0.95 : 0.0);

  document.getElementById("toggleLabels").onchange = () => {
    const op = labelsOn() ? 0.95 : 0.0;
    text.attr("opacity", op);
    textHalo.attr("opacity", op);
  };

  // tick updates
  sim.on("tick", () => {
    link
      .attr("x1", d => (nodeById.get(d.source.id || d.source) || {}).x)
      .attr("y1", d => (nodeById.get(d.source.id || d.source) || {}).y)
      .attr("x2", d => (nodeById.get(d.target.id || d.target) || {}).x)
      .attr("y2", d => (nodeById.get(d.target.id || d.target) || {}).y);

    node.attr("cx", d => d.x).attr("cy", d => d.y);

    text.attr("x", d => d.x).attr("y", d => d.y);
    textHalo.attr("x", d => d.x).attr("y", d => d.y);
  });
}


//listing podle cve, malware atp
async function loadList(kind) {
  const map = {
    hosts: "/api/list/hosts?limit=300",
    cves: "/api/list/cves?limit=500",
    malware: "/api/list/malware?limit=500",
    intrusion: "/api/list/intrusion-sets?limit=500",
    nvts: "/api/list/nvts?limit=500",
  };

  const data = await apiJson(map[kind]);
  if (!data) return;
  renderList(kind, data.results || []);
}

function renderList(kind, items) {
  const el = document.getElementById("leftList");
  el.innerHTML = "";
  items.forEach(it => {
    const div = document.createElement("div");
    div.className = "item";
    div.textContent = it.title;
    div.onclick = () => loadGraph(it.id);
    el.appendChild(div);
  });
}



// pin/unpin all (klávesa P)
document.addEventListener("keydown", (e) => {
  if (e.key.toLowerCase() !== "p") return;
  if (!currentSim || !currentNodes.length) return;

  const pinnedCount = currentNodes.filter(n => n.fx != null && n.fy != null).length;
  const shouldUnpin = pinnedCount > currentNodes.length * 0.5;

  currentNodes.forEach(n => {
    if (shouldUnpin) {
      n.fx = null;
      n.fy = null;
      n.pinned = false;
    } else {
      n.fx = n.x;
      n.fy = n.y;
      n.pinned = true;
    }
  });

  currentSim.alpha(0.6).restart();
});

// wiring
document.getElementById("btn").onclick = doSearch;
document.getElementById("q").addEventListener("keydown", (e) => {
  if (e.key === "Enter") doSearch();
});
