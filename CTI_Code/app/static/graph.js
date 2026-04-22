const svg = d3.select("#graph");
const width = () => document.getElementById("graph").clientWidth;
const height = () => document.getElementById("graph").clientHeight;

let sim = null;
let currentNodeId = null;
let currentSelectionKind = null;

const LIST_ENDPOINTS = {
  hosts: "/api/list/hosts?limit=500",
  cves: "/api/list/cves?limit=5000",
  nvts: "/api/list/nvts?limit=900",
  malware: "/api/list/malware?limit=900",
  intrusion: "/api/list/intrusion-sets?limit=900",
  attack: "/api/list/attack-patterns?limit=900",
  locations: "/api/list/locations?limit=900",
  threatclasses: "/api/list/threat-classes?limit=900",
};

const cache = {
  hosts: [],
  cves: [],
  nvts: [],
  malware: [],
  intrusion: [],
  attack: [],
  locations: [],
  threatclasses: [],
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
  if (labels.includes("ThreatClass")) return "ThreatClass";
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
    ThreatClass: "#ff6b6b",
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

function hasAnyLabel(node, labels) {
  const nodeLabels = node?.labels || [];
  return labels.some(label => nodeLabels.includes(label));
}

function buildAdjacency(edges) {
  const adj = new Map();
  const push = (a, b, edge) => {
    if (!adj.has(a)) adj.set(a, []);
    adj.get(a).push({ otherId: b, edge });
  };

  for (const edge of edges || []) {
    if (!edge?.source || !edge?.target) continue;
    push(edge.source, edge.target, edge);
    push(edge.target, edge.source, edge);
  }
  return adj;
}

function collectNeighborsByLabel(adj, nodesById, sourceIds, labels) {
  const out = new Set();
  for (const sourceId of sourceIds) {
    const neigh = adj.get(sourceId) || [];
    for (const n of neigh) {
      const node = nodesById.get(n.otherId);
      if (node && hasAnyLabel(node, labels)) out.add(node.id);
    }
  }
  return out;
}

function looksLikeCve(value) {
  return /^CVE-\d{4}-\d+/i.test(String(value || "").trim());
}

function nodeLooksLikeCve(node) {
  if (!node) return false;
  return hasAnyLabel(node, ["CVE", "Vulnerability"]) || looksLikeCve(node.id) || looksLikeCve(node.title);
}

function nodeLooksLikeNvt(node) {
  if (!node) return false;
  return hasAnyLabel(node, ["NVT"]);
}

function nodeLooksLikeAttackPattern(node) {
  if (!node) return false;
  return hasAnyLabel(node, ["AttackPattern"]);
}

function truncateText(value, maxWords = 3) {
  const txt = String(value || "").trim();
  if (!txt) return "";
  const words = txt.split(/\s+/).filter(Boolean);
  if (words.length <= maxWords) return txt;
  return `${words.slice(0, maxWords).join(" ")} ...`;
}

function formatTagsRawForModal(tagsRaw) {
  const raw = String(tagsRaw || "");
  if (!raw) return "";
  const parts = raw.split("|").map(x => x.trim()).filter(Boolean);
  const vec = parts.find(x => x.startsWith("cvss_base_vector="));
  const rest = parts.filter(x => x !== vec);
  return [vec || "", rest.join("\n")].filter(Boolean).join("\n\n");
}

function ensureCtxModal() {
  let modal = document.getElementById("ctxModal");
  if (modal) return modal;

  modal = document.createElement("dialog");
  modal.id = "ctxModal";
  modal.innerHTML = `
    <div class="ctx-modal-head">
      <span id="ctxModalTitle">Detail</span>
      <button class="ctx-modal-close" id="ctxModalClose">×</button>
    </div>
    <pre id="ctxModalText"></pre>
  `;
  document.body.appendChild(modal);
  modal.querySelector("#ctxModalClose").addEventListener("click", () => modal.close());
  return modal;
}

function openCtxModal(title, text) {
  const modal = ensureCtxModal();
  modal.querySelector("#ctxModalTitle").textContent = title;
  modal.querySelector("#ctxModalText").textContent = String(text || "");
  modal.showModal();
}

function addExpandableField(parent, label, value, formatter = (x) => String(x || "")) {
  const text = formatter(value);
  if (!text) return;

  const box = document.createElement("div");
  box.className = "ctx-kv";

  const lbl = document.createElement("b");
  lbl.textContent = `${label}:`;
  box.appendChild(lbl);

  const preview = document.createElement("span");
  const previewText = truncateText(text, 3);
  preview.textContent = ` ${previewText}`;
  box.appendChild(preview);

  if (previewText !== text) {
    const link = document.createElement("a");
    link.className = "ctx-expand";
    link.href = "#";
    link.textContent = "show all";
    link.addEventListener("click", (e) => {
      e.preventDefault();
      openCtxModal(label, text);
    });
    box.appendChild(link);
  }

  parent.appendChild(box);
}

function extractAttackPatternUrl(props) {
  const direct = String(props?.url || "").trim();
  if (direct) return direct;

  const refs = props?.external_references;
  if (Array.isArray(refs)) {
    const hit = refs.find(x => typeof x?.url === "string" && x.url.startsWith("http"));
    if (hit) return hit.url;
  }
  const refsText = String(refs || "");
  const m = refsText.match(/https?:\/\/attack\.mitre\.org\/[^\s"\\]+/i);
  return m ? m[0] : "";
}

function renderContextHighlights(data) {
  const wrap = document.getElementById("ctxHighlights");
  wrap.innerHTML = "";
  const props = data?.props || {};
  const labels = data?.labels || [];

  if (labels.includes("AttackPattern") || nodeLooksLikeAttackPattern(data)) {
    const url = extractAttackPatternUrl(props);
    if (url) {
      const linkWrap = document.createElement("div");
      linkWrap.className = "ctx-link";
      const lbl = document.createElement("b");
      lbl.textContent = "URL:";
      linkWrap.appendChild(lbl);
      linkWrap.appendChild(document.createTextNode(" "));
      const a = document.createElement("a");
      a.href = url;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.textContent = url;
      linkWrap.appendChild(a);
      wrap.appendChild(linkWrap);
    }
  }

  if (labels.includes("NVT") || nodeLooksLikeNvt(data)) {
    const cvss = String(props.cvss_base || "").trim();
    const family = String(props.family || "").trim();
    if (cvss || family) {
      const kv = document.createElement("div");
      kv.className = "ctx-kv";
      if (cvss) {
        const cvssLbl = document.createElement("b");
        cvssLbl.textContent = "CVSS:";
        kv.appendChild(cvssLbl);
        kv.appendChild(document.createTextNode(` ${cvss}`));
      }
      if (family) {
        if (cvss) kv.appendChild(document.createElement("br"));
        const famLbl = document.createElement("b");
        famLbl.textContent = "Family:";
        kv.appendChild(famLbl);
        kv.appendChild(document.createTextNode(` ${family}`));
      }
      wrap.appendChild(kv);
    }
    addExpandableField(wrap, "SOLUTION", props.solution);
    addExpandableField(wrap, "Summary", props.summary);
    addExpandableField(wrap, "Tags_Raw", props.tags_raw, formatTagsRawForModal);
  }
}

function resolveAnchorIds(nodes, selectedNodeId, mode) {
  const selectedNorm = String(selectedNodeId || "").trim().toUpperCase();
  const out = new Set();

  for (const node of nodes) {
    const byMode = mode === "cve" ? nodeLooksLikeCve(node) : nodeLooksLikeNvt(node);
    if (!byMode) continue;

    const nid = String(node.id || "").toUpperCase();
    const ntitle = String(node.title || "").toUpperCase();
    if (
      nid === selectedNorm ||
      ntitle === selectedNorm ||
      nid.startsWith(selectedNorm) ||
      ntitle.startsWith(selectedNorm)
    ) {
      out.add(node.id);
    }
  }

  return out;
}

function filterGraphForFocusedPath(rawData, selectedNodeId, hops, selectionKind) {
  // Pro CVE/NVT výběr omezíme graf jen na "čistou" CTI cestu:
  // Host -> CVE -> NVT -> (IntrusionSet|Malware) -> (AttackPattern|Location)
  if (hops <= 1) return rawData;

  const nodes = rawData?.nodes || [];
  const edges = rawData?.edges || [];
  const nodesById = new Map(nodes.map(n => [n.id, n]));
  const adj = buildAdjacency(edges);
  const selected = nodesById.get(selectedNodeId);

  const isCveMode =
    selectionKind === "cves" ||
    selectionKind === "cve" ||
    looksLikeCve(selectedNodeId) ||
    nodeLooksLikeCve(selected);
  const isNvtMode =
    selectionKind === "nvts" ||
    selectionKind === "nvt" ||
    nodeLooksLikeNvt(selected);

  if (!isCveMode && !isNvtMode) return rawData;

  const cveAnchors = isCveMode ? resolveAnchorIds(nodes, selectedNodeId, "cve") : new Set();
  const nvtAnchors = isNvtMode ? resolveAnchorIds(nodes, selectedNodeId, "nvt") : new Set();

  if (!cveAnchors.size && !nvtAnchors.size) return rawData;

  // doplnění druhé strany triády (CVE <-> NVT)
  const cveFromNvt = collectNeighborsByLabel(adj, nodesById, nvtAnchors, ["CVE", "Vulnerability"]);
  const nvtFromCve = collectNeighborsByLabel(adj, nodesById, cveAnchors, ["NVT"]);
  const cveIds = new Set([...cveAnchors, ...cveFromNvt]);
  const nvtIds = new Set([...nvtAnchors, ...nvtFromCve]);

  // hosty bereme z obou stran (z NVT i z CVE)
  const hostFromCve = collectNeighborsByLabel(adj, nodesById, cveIds, ["Host"]);
  const hostFromNvt = collectNeighborsByLabel(adj, nodesById, nvtIds, ["Host"]);
  const hostIds = new Set([...hostFromCve, ...hostFromNvt]);

  const keep = new Set([...cveIds, ...nvtIds, ...hostIds]);
  const ctiSeed = new Set([...cveIds, ...nvtIds]);
  const intrusionIds = collectNeighborsByLabel(adj, nodesById, ctiSeed, ["IntrusionSet"]);
  const malwareIds = collectNeighborsByLabel(adj, nodesById, ctiSeed, ["Malware"]);
  const actorIds = new Set([...intrusionIds, ...malwareIds]);
  const attackIds = collectNeighborsByLabel(adj, nodesById, actorIds, ["AttackPattern"]);
  const locationIds = collectNeighborsByLabel(adj, nodesById, actorIds, ["Location"]);
  const threatIds = collectNeighborsByLabel(adj, nodesById, ctiSeed, ["ThreatClass"]);
  const hostFromThreat = collectNeighborsByLabel(adj, nodesById, threatIds, ["Host"]);
  for (const id of hostFromThreat) hostIds.add(id);

  [
    intrusionIds,
    malwareIds,
    attackIds,
    locationIds,
    threatIds,
  ].forEach(setRef => {
    for (const id of setRef) keep.add(id);
  });

  const inSet = (setRef, id) => setRef.has(id);
  const isAllowedEdge = (a, b) => {
    const inHost = inSet(hostIds, a) || inSet(hostIds, b);
    const inCve = inSet(cveIds, a) || inSet(cveIds, b);
    const inNvt = inSet(nvtIds, a) || inSet(nvtIds, b);
    const inIntr = inSet(intrusionIds, a) || inSet(intrusionIds, b);
    const inMal = inSet(malwareIds, a) || inSet(malwareIds, b);
    const inAct = inIntr || inMal;
    const inAtt = inSet(attackIds, a) || inSet(attackIds, b);
    const inLoc = inSet(locationIds, a) || inSet(locationIds, b);
    const inThreat = inSet(threatIds, a) || inSet(threatIds, b);

    if (inHost && inCve) return true; // Host <-> CVE
    if (inHost && inNvt) return true; // Host <-> NVT (kvůli scan vazbě)
    if (inHost && inThreat) return true; // Host <-> ThreatClass
    if (inCve && inNvt) return true;  // CVE <-> NVT
    if (inCve && inAct) return true;  // CVE <-> IntrusionSet/Malware
    if (inCve && inThreat) return true; // CVE <-> ThreatClass
    if (inNvt && inAct) return true;  // NVT <-> IntrusionSet/Malware
    if (inNvt && inThreat) return true; // NVT <-> ThreatClass
    if (inAct && inAtt) return true;  // Actor <-> AttackPattern
    if (inAct && inLoc) return true;  // Actor <-> Location
    return false;
  };

  const filteredNodes = nodes.filter(n => keep.has(n.id));
  const filteredEdges = edges.filter(e => {
    if (!keep.has(e.source) || !keep.has(e.target)) return false;
    return isAllowedEdge(e.source, e.target);
  });

  return {
    ...rawData,
    nodes: filteredNodes,
    edges: filteredEdges,
  };
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

  const gLinks = svg.append("g").attr("stroke", "#8f97a8").attr("stroke-opacity", 0.7);
  const gNodes = svg.append("g");
  const gLabels = svg.append("g");

  const link = gLinks.selectAll("line")
    .data(links)
    .join("line")
    .attr("stroke-width", 1.2);

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
    div.onclick = () => {
      currentSelectionKind = null;
      loadGraph(r.id);
    };
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
    const maxEdges = Math.min(Math.max(maxNodes * 12, 1200), 25000);

    currentNodeId = nodeId;
    const url = `/api/graph?node_id=${encodeURIComponent(nodeId)}&hops=${hops}&max_nodes=${maxNodes}&max_edges=${maxEdges}`;
    const data = await apiJson(url);
    const filtered = filterGraphForFocusedPath(data, nodeId, hops, currentSelectionKind);
    drawGraph(filtered);
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
    div.onclick = () => {
      currentSelectionKind = kind;
      loadGraph(item.id);
    };
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
  const propsEl = document.getElementById("ctxProps");
  panel.style.display = "block";

  document.getElementById("ctxTitle").textContent = nodeLabel(node);
  document.getElementById("ctxMeta").textContent = `${(node.labels || []).join(", ")} | id=${node.id}`;
  document.getElementById("ctxHighlights").innerHTML = "";
  propsEl.classList.remove("nvt-compact");
  propsEl.textContent = "Loading...";
  document.getElementById("ctxNeigh").innerHTML = "Loading...";

  try {
    const data = await apiJson(`/api/node?id=${encodeURIComponent(node.id)}&neigh_limit=120`);
    document.getElementById("ctxTitle").textContent = nodeLabel(data);
    document.getElementById("ctxMeta").textContent = `${(data.labels || []).join(", ")} | id=${data.id}`;
    renderContextHighlights(data);
    if (nodeLooksLikeNvt(data)) propsEl.classList.add("nvt-compact");
    propsEl.textContent = JSON.stringify(data.props || {}, null, 2);

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
    propsEl.textContent = err.message;
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
    loadList("threatclasses"),
  ]);



  if (cache.hosts.length) {
    loadGraph(cache.hosts[0].id);
  }
}

bootstrap();
