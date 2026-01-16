// app/static/graph.js

const svg = d3.select("#graph");
let width = svg.node().clientWidth;
let height = svg.node().clientHeight;

// cache posledního grafu kvůli toggle bez reloadu
let lastGraph = { nodes: [], edges: [], highlight: { node_ids: [], edge_keys: [] } };

window.addEventListener("resize", () => {
  width = svg.node().clientWidth;
  height = svg.node().clientHeight;
  if (lastGraph.nodes.length) draw(lastGraph.nodes, lastGraph.edges, lastGraph.highlight);
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

function hexToRgba(hex, a) {
  const h = (hex || "").replace("#", "");
  if (h.length !== 6) return `rgba(0,0,0,${a})`;
  const r = parseInt(h.slice(0, 2), 16);
  const g = parseInt(h.slice(2, 4), 16);
  const b = parseInt(h.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${a})`;
}

// --- edge key helpers for highlight ---
function edgeKeyFromParts(s, type, t) {
  return `${s}|${type}|${t}`;
}
function edgeKey(e) {
  const s = (e.source && e.source.id) ? e.source.id : e.source;
  const t = (e.target && e.target.id) ? e.target.id : e.target;
  return edgeKeyFromParts(s, e.type, t);
}
function edgeKeyReverse(e) {
  const s = (e.source && e.source.id) ? e.source.id : e.source;
  const t = (e.target && e.target.id) ? e.target.id : e.target;
  return edgeKeyFromParts(t, e.type, s);
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

function ensurePathOnlyToggle() {
  if (document.getElementById("togglePathOnly")) return;

  const header = document.querySelector("header");
  if (!header) return;

  const wrap = document.createElement("label");
  wrap.style.marginLeft = "10px";
  wrap.style.fontSize = "12px";
  wrap.style.opacity = "0.85";
  wrap.innerHTML = `<input id="togglePathOnly" type="checkbox" style="vertical-align: middle; margin-right: 6px;">schovat nepřímé uzly`;
  header.appendChild(wrap);

  wrap.querySelector("input").addEventListener("change", () => {
    if (lastGraph.nodes.length) draw(lastGraph.nodes, lastGraph.edges, lastGraph.highlight);
  });
}

function ensureDimToggle() {
  if (document.getElementById("toggleDimIndirect")) return;

  const header = document.querySelector("header");
  if (!header) return;

  const wrap = document.createElement("label");
  wrap.style.marginLeft = "10px";
  wrap.style.fontSize = "12px";
  wrap.style.opacity = "0.85";
  wrap.innerHTML = `<input id="toggleDimIndirect" type="checkbox" style="vertical-align: middle; margin-right: 6px;">utlumit nepřímé uzly`;
  header.appendChild(wrap);

  wrap.querySelector("input").addEventListener("change", () => {
    if (lastGraph.nodes.length) draw(lastGraph.nodes, lastGraph.edges, lastGraph.highlight);
  });
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
  legend.style.maxWidth = "360px";
  legend.style.zIndex = "9998";

  const rows = [
    ["USES", edgeColor("USES")],
    ["TARGETS", edgeColor("TARGETS")],
    ["IS", edgeColor("IS")],
    ["REFERS_TO", edgeColor("REFERS_TO")],
    ["VULNERABLE_TO", edgeColor("VULNERABLE_TO")],
    ["HAS_NVT", edgeColor("HAS_NVT")],
  ];

  legend.innerHTML = `
    <div style="font-weight:700; margin-bottom:8px;">Legend</div>
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
      <div><b>SHIFT+klik</b>: drill-down (subgraph)</div>
      <div style="margin-top:6px;"><b>schovat nepřímé uzly</b>: ukáže jen cestu k Hostovi</div>
      <div><b>utlumit nepřímé uzly</b>: ponechá vše, ale mimo cestu zeslabí (vč. šipek)</div>
    </div>
  `;
  document.body.appendChild(legend);
}

// ---------- Context panel ----------
function showCtxPanel(node) {
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

document.getElementById("ctxClose").onclick = () => {
  document.getElementById("ctx").style.display = "none";
};

// ---------- API ----------
async function apiJson(url) {
  const res = await fetch(url);
  if (!res.ok) {
    const txt = await res.text();
    console.error("API error:", res.status, txt);
    alert(`API error ${res.status}:\n${txt.slice(0, 400)}`);
    return null;
  }
  return await res.json();
}

// ---------- Search (fulltext) ----------
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

// ---------- Lists (Evidence vs CTI) ----------
const LIST_ENDPOINTS = {
  hosts: "/api/list/hosts?limit=500",
  cves: "/api/list/cves?limit=800",
  nvts: "/api/list/nvts?limit=800",
  malware: "/api/list/malware?limit=800",
  intrusion: "/api/list/intrusion-sets?limit=800",
};

const cache = { hosts: [], cves: [], nvts: [], malware: [], intrusion: [] };

function renderList(kind, items) {
  const el = document.getElementById(`list_${kind}`);
  if (!el) {
    console.error("renderList: missing element", `list_${kind}`);
    return;
  }

  el.innerHTML = "";
  items.forEach(it => {
    const div = document.createElement("div");
    div.className = "item";
    div.textContent = it.title;
    div.onclick = () => loadGraph(it.id);
    el.appendChild(div);
  });
}

function wireFilter(kind) {
  const input = document.getElementById(`filter_${kind}`);
  if (!input) return;

  input.addEventListener("input", () => {
    const q = input.value.trim().toLowerCase();
    const src = cache[kind] || [];
    if (!q) return renderList(kind, src);

    const filtered = src.filter(x => (x.title || "").toLowerCase().includes(q));
    renderList(kind, filtered);
  });
}

async function loadList(kind) {
  const url = LIST_ENDPOINTS[kind];
  const data = await apiJson(url);
  if (!data) return;

  cache[kind] = data.results || [];
  renderList(kind, cache[kind]);
  wireFilter(kind);
}

// ---------- Graph load ----------
async function loadGraph(node_id) {
  const radius = parseInt(document.getElementById("radius").value || "2", 10);

  const data = await apiJson(
    `/api/graph?node_id=${encodeURIComponent(node_id)}&radius=${radius}&max_nodes=400`
    + `&highlight_hosts=1&path_max_hops=6`
  );
  if (!data) return;

  lastGraph = {
    nodes: data.nodes || [],
    edges: data.edges || [],
    highlight: data.highlight || { node_ids: [], edge_keys: [] }
  };

  draw(lastGraph.nodes, lastGraph.edges, lastGraph.highlight);
}

async function loadNodeDetails(node) {
  showCtxPanel(node);
  const details = await apiJson(`/api/node?id=${encodeURIComponent(node.id)}&neigh_limit=140`);
  if (details) renderCtxDetails(details);
}

// ---------- draw ----------
let currentSim = null;
let currentNodes = [];

function draw(nodes, edges, highlight) {
  ensureLabelToggle();
  ensurePathOnlyToggle();
  ensureDimToggle();
  ensureLegend();

  highlight = highlight || { node_ids: [], edge_keys: [] };
  const hiNodes = new Set(highlight.node_ids || []);
  const hiEdges = new Set(highlight.edge_keys || []);

  const pathOnly = document.getElementById("togglePathOnly")?.checked ?? false;
  const dimIndirect = document.getElementById("toggleDimIndirect")?.checked ?? false;

  // když je zapnuté "schovat", tak "utlumit" nedává smysl → disable
  const dimBox = document.getElementById("toggleDimIndirect");
  if (dimBox) {
    dimBox.disabled = pathOnly;
    dimBox.parentElement.style.opacity = pathOnly ? "0.45" : "0.85";
  }

  // helpery pro vyhodnocení "main" (hlavní) uzlů/hran
  const isHiNode = (n) => hiNodes.has(n.id);
  const isHiEdge = (e) => hiEdges.has(edgeKey(e)) || hiEdges.has(edgeKeyReverse(e));

  function edgeEnds(e) {
    const s = (e.source && e.source.id) ? e.source.id : e.source;
    const t = (e.target && e.target.id) ? e.target.id : e.target;
    return [s, t];
  }

  const isMainNodeId = (id) => hiNodes.has(id);

  // hrana je "main", když je explicitně v highlight, nebo spojuje 2 highlight uzly
  const isMainEdge = (e) => {
    if (isHiEdge(e)) return true;
    const [s, t] = edgeEnds(e);
    return isMainNodeId(s) && isMainNodeId(t);
  };

  // pokud chceš jen cestu a highlight existuje -> odfiltruj všechno mimo
  if (pathOnly && hiNodes.size > 0) {
    const filteredNodes = (nodes || []).filter(n => hiNodes.has(n.id));
    const filteredEdges = (edges || []).filter(e => {
      const k1 = edgeKeyFromParts(e.source, e.type, e.target);
      const k2 = edgeKeyFromParts(e.target, e.type, e.source);
      return hiEdges.has(k1) || hiEdges.has(k2);
    });
    nodes = filteredNodes;
    edges = filteredEdges;
  }

  currentNodes = nodes;

  // vyčistit SVG
  svg.selectAll("*").remove();

  const g = svg.append("g");
  svg.call(d3.zoom().on("zoom", (event) => g.attr("transform", event.transform)));

  // defs: arrows
  const edgeTypes = Array.from(new Set((edges || []).map(e => e.type))).sort();
  const defs = svg.append("defs");

  // per-type marker: normal / HI / DIM (vždy drží barvy vztahů!)
  edgeTypes.forEach((t) => {
    // normal
    defs.append("marker")
      .attr("id", `arrow-${t}`)
      .attr("viewBox", "0 -5 10 10")
      .attr("refX", 18)
      .attr("refY", 0)
      .attr("markerWidth", 6)
      .attr("markerHeight", 6)
      .attr("orient", "auto")
      .append("path")
      .attr("d", "M0,-5L10,0L0,5")
      .attr("fill", edgeColor(t));

    // HI (větší šipka, pořád barva vztahu)
    defs.append("marker")
      .attr("id", `arrow-${t}-HI`)
      .attr("viewBox", "0 -5 10 10")
      .attr("refX", 18)
      .attr("refY", 0)
      .attr("markerWidth", 9)
      .attr("markerHeight", 9)
      .attr("orient", "auto")
      .append("path")
      .attr("d", "M0,-5L10,0L0,5")
      .attr("fill", edgeColor(t));

    // DIM (vybledlá šipka stejné barvy vztahu)
    defs.append("marker")
      .attr("id", `arrow-${t}-DIM`)
      .attr("viewBox", "0 -5 10 10")
      .attr("refX", 18)
      .attr("refY", 0)
      .attr("markerWidth", 6)
      .attr("markerHeight", 6)
      .attr("orient", "auto")
      .append("path")
      .attr("d", "M0,-5L10,0L0,5")
      .attr("fill", hexToRgba(edgeColor(t), 0.25));
  });

  const nodeById = new Map(nodes.map(n => [n.id, n]));
  const links = (edges || [])
    .filter(e => nodeById.has(e.source) && nodeById.has(e.target))
    .map(e => ({ ...e }));

  // Simulation tuned for readability
  const sim = d3.forceSimulation(nodes)
    .alphaMin(0.06)
    .alphaDecay(0.12)
    .velocityDecay(0.55)
    .force("link", d3.forceLink(links).id(d => d.id).distance(85).strength(0.95))
    .force("charge", d3.forceManyBody().strength(-110))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("collide", d3.forceCollide().radius(d => radiusFor(d) + 14).iterations(2))
    .force("x", d3.forceX(width / 2).strength(0.10))
    .force("y", d3.forceY(height / 2).strength(0.10));

  currentSim = sim;

  // hard stop, aby se to po chvíli přestalo hýbat
  setTimeout(() => {
    if (!currentSim) return;
    currentSim.alphaTarget(0);
    currentSim.stop();
  }, 1600);

  // ----- EDGES: barvy vztahů vždy zachované, highlight jen tloušťkou/opacitou/velikostí šipky -----
  const link = g.selectAll("line")
    .data(links)
    .enter()
    .append("line")
    .attr("stroke", d => {
      const c = edgeColor(d.type);
      if (dimIndirect && !isMainEdge(d)) return hexToRgba(c, 0.18); // tlumené, ale pořád "barva vztahu"
      return c;                                                    // normál + main
    })
    .attr("stroke-width", d => {
      if (isMainEdge(d)) return 4.5;
      if (dimIndirect) return 1.0;
      return 1.8;
    })
    .attr("opacity", d => {
      if (isMainEdge(d)) return 0.95;
      if (dimIndirect) return 0.22;   // tlumené, ale viditelné
      return 0.85;
    })
    .attr("marker-end", d => {
      if (isMainEdge(d)) return `url(#arrow-${d.type}-HI)`;   // velká šipka stejné barvy vztahu
      if (dimIndirect) return `url(#arrow-${d.type}-DIM)`;    // vybledlá šipka stejné barvy vztahu
      return `url(#arrow-${d.type})`;
    });

  link.append("title").text(d => d.type);

  // drag: keep pinned
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
    d.pinned = true;
  }

  // ----- NODES: default normál, dim jen když checkbox -----
  const node = g.selectAll("circle")
    .data(nodes)
    .enter()
    .append("circle")
    .attr("r", d => {
      const base = radiusFor(d);
      const isHost = (d.labels || []).includes("Host");
      const hi = isHiNode(d);

      if (isHost && hi) return base + 10;
      if (isHost) return base + 6;
      if (hi) return base + 4;
      return base;
    })
    .attr("fill", d => nodeColor(d))
    .attr("opacity", d => {
      if (pathOnly) return 1.0;
      if (!dimIndirect) return 1.0;          // NORMAL = nic není vybledlé
      return isHiNode(d) ? 1.0 : 0.18;       // DIM
    })
    .attr("stroke", d => (isHiNode(d) ? "rgba(0,0,0,0.55)" : "rgba(0,0,0,0.20)"))
    .attr("stroke-width", d => (isHiNode(d) ? 2.2 : 1.0))
    .on("click", async (event, d) => {
      if (event.shiftKey) {
        await loadGraph(d.id);
      } else {
        await loadNodeDetails(d);
      }
    })
    .on("dblclick", (_, d) => {
      d.fx = null;
      d.fy = null;
      d.pinned = false;
      sim.alpha(0.5).restart();
    })
    .call(d3.drag().on("start", dragstarted).on("drag", dragged).on("end", dragended));

  node.append("title").text(d => `${d.title}\n${labelOf(d)}\n${d.id}`);

  // ----- LABELS: default normál, dim jen když checkbox -----
  const labelsOn = () => document.getElementById("toggleLabels")?.checked ?? true;
  const labelGroup = g.append("g");

  const labelOpacity = (d) => {
    if (!labelsOn()) return 0.0;
    if (pathOnly) return 0.95;
    if (!dimIndirect) return 0.95;
    return isHiNode(d) ? 0.95 : 0.10;
  };

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
    .attr("opacity", d => labelOpacity(d));

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
    .attr("opacity", d => labelOpacity(d));

  document.getElementById("toggleLabels").onchange = () => {
    text.attr("opacity", d => labelOpacity(d));
    textHalo.attr("opacity", d => labelOpacity(d));
  };

  // ticks
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

// pin/unpin all (P)
document.addEventListener("keydown", (e) => {
  const k = (e.key || "").toLowerCase();
  if (k !== "p") return;
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

// init search
function initSearch() {
  const btn = document.getElementById("btn");
  const q = document.getElementById("q");
  if (!btn || !q) {
    console.error("initSearch: missing #btn or #q");
    return;
  }

  btn.addEventListener("click", (e) => {
    e.preventDefault();
    doSearch();
  });

  q.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      doSearch();
    }
  });
}

async function initLists() {
  initSearch();
  await loadList("hosts");
  await loadList("cves");
  await loadList("nvts");
  await loadList("malware");
  await loadList("intrusion");
}

// když už DOMContentLoaded proběhl, spusť hned
if (document.readyState === "loading") {
  window.addEventListener("DOMContentLoaded", initLists);
} else {
  initLists();
}
