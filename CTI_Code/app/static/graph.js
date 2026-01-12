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
  legend.style.maxWidth = "320px";

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
    <div style="margin-top:8px; opacity:.8; line-height:1.3;">
      <div><b>Drag</b>: uzel se “připíchne” (zůstane na místě)</div>
      <div><b>Dvojklik</b>: unpin (vrátí se do simulace)</div>
      <div><b>P</b>: pin/unpin ALL</div>
    </div>
  `;

  document.body.appendChild(legend);
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

// ---------- draw ----------
let currentSim = null;
let currentNodes = [];
let currentTexts = null;
let currentNodeSel = null;

function draw(nodes, edges) {
  ensureLabelToggle();
  ensureLegend();

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

  // Force simulation: méně "chumlu", víc prostoru pro labely
  const sim = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id(d => d.id).distance(95))
    .force("charge", d3.forceManyBody().strength(-180))         // méně agresivní
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("collide", d3.forceCollide().radius(d => radiusFor(d) + 12)) // víc místa pro text
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

  // drag behavior: PO PUŠTĚNÍ UZEL ZŮSTANE (pin)
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
    // NEVRACÍME fx/fy na null => uzel zůstane tam, kam ho pustíš
    if (!event.active) sim.alphaTarget(0);
    d.pinned = true;
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
    .on("click", (_, d) => loadGraph(d.id)) // drill-down
    .on("dblclick", (_, d) => {             // unpin
      d.fx = null;
      d.fy = null;
      d.pinned = false;
      sim.alpha(0.4).restart();
    })
    .call(d3.drag().on("start", dragstarted).on("drag", dragged).on("end", dragended));

  currentNodeSel = node;

  node.append("title").text(d => `${d.title}\n${labelOf(d)}\n${d.id}`);

  // labels toggle
  const labelsOn = () => document.getElementById("toggleLabels")?.checked ?? true;

  // “halo” pro čitelnost labelů
  const labelGroup = g.append("g");

  const textHalo = labelGroup.selectAll("text.halo")
    .data(nodes)
    .enter()
    .append("text")
    .attr("class", "halo")
    .text(d => (d.title ? String(d.title).slice(0, 40) : d.id))
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
    .text(d => (d.title ? String(d.title).slice(0, 40) : d.id))
    .attr("font-size", 11)
    .attr("dx", 14)
    .attr("dy", 4)
    .attr("pointer-events", "none")
    .attr("fill", "#111")
    .attr("opacity", labelsOn() ? 0.95 : 0.0);

  currentTexts = { text, textHalo };

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

// pin/unpin all (klávesa P)
document.addEventListener("keydown", (e) => {
  if (e.key.toLowerCase() !== "p") return;
  if (!currentSim || !currentNodes.length) return;

  // zjisti, jestli je většina už pin
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
