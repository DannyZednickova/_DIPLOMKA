const svg = d3.select("#graph");
const width = () => document.getElementById("graph").clientWidth;
const height = () => document.getElementById("graph").clientHeight;

let sim = null;
let currentNodeId = null;

const LIST_ENDPOINTS = {
  hosts: "/api/list/hosts?limit=500",
  cves: "/api/list/cves?limit=900",
  nvts: "/api/list/nvts?limit=900",
  malware: "/api/list/malware?limit=900",
  intrusion: "/api/list/intrusion-sets?limit=900",
  attack: "/api/list/attack-patterns?limit=900",
  locations: "/api/list/locations?limit=900",
};

const cache = {
  hosts: [],
  cves: [],
  nvts: [],
  malware: [],
  intrusion: [],
  attack: [],
  locations: [],
};

function nodeLabel(node) {
  return node?.title || node?.id || "unknown";
}

function majorLabel(node) {
  const labels = node?.labels || [];
  if (labels.includes("Host")) return "Host";
  if (labels.includes("Vulnerability")) return "Vulnerability";
  if (labels.includes("CVE")) return "CVE";
  if (labels.includes("NVT")) return "NVT";
  if (labels.includes("Malware")) return "Malware";
  if (labels.includes("IntrusionSet")) return "IntrusionSet";
  if (labels.includes("AttackPattern")) return "AttackPattern";
  if (labels.includes("Location")) return "Location";
  return labels[0] || "Other";
}

function nodeColor(node) {
  const key = majorLabel(node);
  const map = {
    Host: "#bb6bd9",
    Vulnerability: "#34c9d8",
    CVE: "#34c9d8",
    NVT: "#77d645",
    Malware: "#c980e5",
    IntrusionSet: "#26b8d4",
    AttackPattern: "#9ce1e8",
    Location: "#f6c266",
    Other: "#9aa2b0",
  };
  return map[key] || map.Other;
}

async function apiJson(url) {
  const res = await fetch(url);
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`API ${res.status}: ${txt.slice(0, 400)}`);
  }
  return await res.json();
}

function drawGraph(data) {
  svg.selectAll("*").remove();

  const nodes = (data.nodes || []).map(d => ({ ...d }));
  const links = (data.edges || []).map(d => ({ ...d }));

  if (!nodes.length) {
    svg.append("text")
      .attr("x", 20)
      .attr("y", 30)
      .attr("fill", "#666")
      .text("No data for selected node/hops.");
    return;
  }

  const gLinks = svg.append("g").attr("stroke", "#b2b7c2").attr("stroke-opacity", 0.45);
  const gNodes = svg.append("g");
  const gLabels = svg.append("g");

  const link = gLinks.selectAll("line")
    .data(links)
    .join("line")
    .attr("stroke-width", 1);

  const node = gNodes.selectAll("circle")
    .data(nodes)
    .join("circle")
    .attr("r", d => d.id === currentNodeId ? 8 : 5)
    .attr("fill", d => nodeColor(d))
    .attr("stroke", d => d.id === currentNodeId ? "#111" : "#fff")
    .attr("stroke-width", d => d.id === currentNodeId ? 2.2 : 1.1)
    .call(drag());

  node.append("title").text(d => `${nodeLabel(d)}\n${(d.labels || []).join(", ")}`);

  const text = gLabels.selectAll("text")
    .data(nodes)
    .join("text")
    .text(d => nodeLabel(d))
    .attr("font-size", 10)
    .attr("fill", "#273043")
    .attr("stroke", "#fff")
    .attr("stroke-width", 0.25)
    .attr("paint-order", "stroke");

  sim = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id(d => d.id).distance(60).strength(0.24))
    .force("charge", d3.forceManyBody().strength(-160))
    .force("center", d3.forceCenter(width() / 2, height() / 2))
    .force("collide", d3.forceCollide(10))
    .on("tick", () => {
      link
        .attr("x1", d => d.source.x)
        .attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x)
        .attr("y2", d => d.target.y);

      node
        .attr("cx", d => d.x)
        .attr("cy", d => d.y);

      text
        .attr("x", d => d.x + 7)
        .attr("y", d => d.y - 7);
    });

  node.on("click", async (event, d) => {
    if (event.shiftKey) {
      await loadGraph(d.id);
      return;
    }
    await openCtx(d);
  });

  svg.call(
    d3.zoom().scaleExtent([0.1, 4]).on("zoom", ({ transform }) => {
      gLinks.attr("transform", transform);
      gNodes.attr("transform", transform);
      gLabels.attr("transform", transform);
    })
  );
}

function drag() {
  function started(event, d) {
    if (!event.active) sim.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
  }

  function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
  }

  function ended(event, d) {
    if (!event.active) sim.alphaTarget(0);
    d.fx = null;
    d.fy = null;
  }

  return d3.drag().on("start", started).on("drag", dragged).on("end", ended);
}

function renderResults(results) {
  const el = document.getElementById("results");
  el.innerHTML = "";
  for (const r of results) {
    const div = document.createElement("div");
    div.className = "item";
    div.textContent = `${r.title} [${(r.labels || []).join(", ")}] score=${Number(r.score || 0).toFixed(2)}`;
    div.onclick = () => loadGraph(r.id);
    el.appendChild(div);
  }
}

async function doSearch() {
  try {
    const q = document.getElementById("q").value.trim();
    if (q.length < 2) return;
    const data = await apiJson(`/api/search?q=${encodeURIComponent(q)}&limit=40`);
    renderResults(data.results || []);
  } catch (err) {
    alert(err.message);
  }
}

async function loadGraph(nodeId) {
  try {
    const hops = Number(document.getElementById("hops").value || 2);
    const maxNodes = Number(document.getElementById("maxNodes").value || 1200);

    currentNodeId = nodeId;
    const url = `/api/graph?node_id=${encodeURIComponent(nodeId)}&hops=${hops}&max_nodes=${maxNodes}`;
    const data = await apiJson(url);
    drawGraph(data);
  } catch (err) {
    alert(err.message);
  }
}

function renderList(kind, items) {
  const el = document.getElementById(`list_${kind}`);
  if (!el) return;
  el.innerHTML = "";

  for (const item of items) {
    const div = document.createElement("div");
    div.className = "item";
    div.textContent = item.title;
    div.onclick = () => loadGraph(item.id);
    el.appendChild(div);
  }
}

function wireFilter(kind) {
  const inp = document.getElementById(`filter_${kind}`);
  if (!inp) return;

  inp.addEventListener("input", () => {
    const q = inp.value.trim().toLowerCase();
    const src = cache[kind] || [];
    if (!q) {
      renderList(kind, src);
      return;
    }
    renderList(kind, src.filter(x => (x.title || "").toLowerCase().includes(q)));
  });
}

async function loadList(kind) {
  try {
    const data = await apiJson(LIST_ENDPOINTS[kind]);
    cache[kind] = data.results || [];
    renderList(kind, cache[kind]);
    wireFilter(kind);
  } catch (err) {
    const el = document.getElementById(`list_${kind}`);
    if (el) {
      el.innerHTML = `<div class='item'>Chyba: ${err.message}</div>`;
    }
  }
}

async function openCtx(node) {
  const panel = document.getElementById("ctx");
  panel.style.display = "block";

  document.getElementById("ctxTitle").textContent = nodeLabel(node);
  document.getElementById("ctxMeta").textContent = `${(node.labels || []).join(", ")} | id=${node.id}`;
  document.getElementById("ctxProps").textContent = "Loading...";
  document.getElementById("ctxNeigh").innerHTML = "Loading...";

  try {
    const data = await apiJson(`/api/node?id=${encodeURIComponent(node.id)}&neigh_limit=120`);
    document.getElementById("ctxTitle").textContent = nodeLabel(data);
    document.getElementById("ctxMeta").textContent = `${(data.labels || []).join(", ")} | id=${data.id}`;
    document.getElementById("ctxProps").textContent = JSON.stringify(data.props || {}, null, 2);

    const neigh = document.getElementById("ctxNeigh");
    neigh.innerHTML = "";

    (data.neighbors || []).forEach(n => {
      const div = document.createElement("div");
      div.className = "item";
      div.style.fontSize = "12px";
      div.textContent = `${n.dir} ${n.rel} → ${n.other_title} [${(n.other_labels || []).join(", ")}]`;
      div.onclick = () => loadGraph(n.other_id);
      neigh.appendChild(div);
    });
  } catch (err) {
    document.getElementById("ctxProps").textContent = err.message;
    document.getElementById("ctxNeigh").innerHTML = "";
  }
}

function bootstrapEvents() {
  document.getElementById("btn").addEventListener("click", doSearch);
  document.getElementById("q").addEventListener("keydown", (e) => {
    if (e.key === "Enter") doSearch();
  });

  document.getElementById("btnReload").addEventListener("click", () => {
    if (!currentNodeId) return;
    loadGraph(currentNodeId);
  });

  document.getElementById("ctxClose").addEventListener("click", () => {
    document.getElementById("ctx").style.display = "none";
  });

  window.addEventListener("resize", () => {
    if (currentNodeId) loadGraph(currentNodeId);
  });
}

async function bootstrap() {
  bootstrapEvents();

  await Promise.all([
    loadList("hosts"),
    loadList("cves"),
    loadList("nvts"),
    loadList("malware"),
    loadList("intrusion"),
    loadList("attack"),
    loadList("locations"),
  ]);

  if (cache.hosts.length) {
    loadGraph(cache.hosts[0].id);
  }
}

bootstrap();