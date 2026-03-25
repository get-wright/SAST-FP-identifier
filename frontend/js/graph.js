import { classColor } from "./utils.js";

function isCytoscapeAvailable() {
  return typeof window.cytoscape !== "undefined";
}

function showEmpty(container, message) {
  container.innerHTML = `<div class="graph-empty">${message}</div>`;
}

let tooltipEl = null;

function getTooltip() {
  if (!tooltipEl) {
    tooltipEl = document.createElement("div");
    tooltipEl.className = "graph-tooltip";
    tooltipEl.style.cssText =
      "position:fixed;padding:6px 10px;background:#1c1917;color:#fafaf9;" +
      "font-size:11px;border-radius:4px;pointer-events:none;z-index:300;" +
      "white-space:pre;display:none;max-width:300px";
    document.body.appendChild(tooltipEl);
  }
  return tooltipEl;
}

function attachTooltip(cy) {
  const tip = getTooltip();
  cy.on("mouseover", "node", (e) => {
    const text = e.target.data("tooltip");
    if (!text) return;
    tip.textContent = text;
    tip.style.display = "block";
  });
  cy.on("mousemove", "node", (e) => {
    tip.style.left = `${e.originalEvent.clientX + 12}px`;
    tip.style.top = `${e.originalEvent.clientY + 12}px`;
  });
  cy.on("mouseout", "node", () => {
    tip.style.display = "none";
  });
}

function ensureDagre() {
  if (window.cytoscapeDagre && !window.__cytoscapeDagreRegistered) {
    window.cytoscape.use(window.cytoscapeDagre);
    window.__cytoscapeDagreRegistered = true;
  }
}

function themeColor(name, fallback) {
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value || fallback;
}

function shortFileLabel(path) {
  if (!path) return "unknown";
  const parts = path.split("/");
  return parts[parts.length - 1] || path;
}

export function renderCallGraph(container, finding) {
  if (!isCytoscapeAvailable()) {
    showEmpty(container, "Graph visualization unavailable");
    return;
  }

  const gc = finding.graphContext;
  if (!gc || (!gc.callers?.length && !gc.callees?.length)) {
    showEmpty(container, "No call graph data available");
    return;
  }

  const elements = [];
  const centerColor = classColor(finding.classification);
  const centerId = gc.enclosing_function || "unknown";

  elements.push({
    data: {
      id: centerId,
      label: centerId,
      type: "center",
      color: centerColor,
      tooltip: `${finding.path}:${finding.line}`,
    },
  });

  elements.push({
    data: {
      id: "_vuln_marker",
      label: "",
      type: "vuln_marker",
      parent: centerId,
      tooltip: `Vulnerable line ${finding.line}`,
    },
  });

  for (const caller of gc.callers || []) {
    const callerId = `caller-${caller.file}:${caller.line}`;
    elements.push({
      data: {
        id: callerId,
        label: caller.function || shortFileLabel(caller.file),
        type: "caller",
        tooltip: `${caller.file}:${caller.line}${caller.function ? `\n${caller.function}` : ""}`,
      },
    });
    elements.push({ data: { source: callerId, target: centerId } });
  }

  for (const callee of gc.callees || []) {
    const calleeId = `callee-${callee}`;
    elements.push({
      data: {
        id: calleeId,
        label: callee,
        type: "callee",
        tooltip: callee,
      },
    });
    elements.push({ data: { source: centerId, target: calleeId } });
  }

  container.innerHTML = "";
  ensureDagre();

  const cy = window.cytoscape({
    container,
    elements,
    style: [
      {
        selector: "node",
        style: {
          label: "data(label)",
          "text-valign": "center",
          "text-halign": "center",
          "font-size": "11px",
          color: "#fafaf9",
          "text-outline-color": "#1c1917",
          "text-outline-width": 1,
          "background-color": "#44403c",
          width: 30,
          height: 30,
        },
      },
      {
        selector: 'node[type="center"]',
        style: {
          "background-color": "data(color)",
          width: 45,
          height: 45,
          "font-size": "12px",
          "font-weight": "bold",
          "border-width": 3,
          "border-color": "data(color)",
        },
      },
      {
        selector: 'node[type="vuln_marker"]',
        style: {
          shape: "diamond",
          "background-color": "#dc2626",
          width: 12,
          height: 12,
          "border-width": 0,
          label: "",
        },
      },
      {
        selector: "edge",
        style: {
          width: 1.5,
          "line-color": "#a8a29e",
          "target-arrow-color": "#a8a29e",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          "arrow-scale": 0.8,
          "transition-property": "line-color, target-arrow-color, width",
          "transition-duration": "0.15s",
        },
      },
      {
        selector: "edge:active, edge:selected",
        style: {
          "line-color": "#78716c",
          "target-arrow-color": "#78716c",
          width: 2.5,
        },
      },
    ],
    layout: {
      name: "dagre",
      rankDir: "LR",
      nodeSep: 40,
      rankSep: 80,
      padding: 20,
    },
    userZoomingEnabled: true,
    userPanningEnabled: true,
    boxSelectionEnabled: false,
  });

  cy.on("mouseover", "edge", (e) => {
    e.target.style({
      "line-color": "#78716c",
      "target-arrow-color": "#78716c",
      width: 2.5,
    });
  });
  cy.on("mouseout", "edge", (e) => {
    e.target.removeStyle("line-color target-arrow-color width");
  });

  attachTooltip(cy);
  cy.fit(undefined, 20);
}

export function renderRelationshipMap(container, findings, onSelectFinding) {
  if (!isCytoscapeAvailable()) {
    showEmpty(container, "Graph visualization unavailable");
    return;
  }

  if (findings.length < 2) {
    showEmpty(container, "Need at least 2 findings for relationship map");
    return;
  }

  const elements = [];

  for (let i = 0; i < findings.length; i += 1) {
    const f = findings[i];
    elements.push({
      data: {
        id: `f-${i}`,
        label: f.rule.length > 25 ? `${f.rule.slice(0, 22)}...` : f.rule,
        color: classColor(f.classification),
        size: 20 + f.confidence * 30,
        tooltip: `${f.rule}\n${f.path}:${f.line}\n${f.classification}`,
        findingIndex: i,
      },
    });
  }

  const added = new Set();
  for (let i = 0; i < findings.length; i += 1) {
    for (let j = i + 1; j < findings.length; j += 1) {
      const rel = findRelation(findings[i], findings[j]);
      if (rel) {
        const key = `${i}-${j}`;
        if (!added.has(key)) {
          added.add(key);
          elements.push({
            data: {
              source: `f-${i}`,
              target: `f-${j}`,
              relType: rel.type,
            },
          });
        }
      }
    }
  }

  container.innerHTML = "";

  const cy = window.cytoscape({
    container,
    elements,
    style: [
      {
        selector: "node",
        style: {
          label: "data(label)",
          "text-valign": "bottom",
          "text-margin-y": 6,
          "font-size": "10px",
          color: themeColor("--text", "#1c1917"),
          "background-color": "data(color)",
          width: "data(size)",
          height: "data(size)",
        },
      },
      {
        selector: "edge",
        style: {
          width: 1.5,
          "line-color": "#a8a29e",
          "curve-style": "bezier",
        },
      },
      {
        selector: 'edge[relType="same_function"]',
        style: {
          width: 3,
          "line-color": "#44403c",
        },
      },
      {
        selector: 'edge[relType="caller_callee"]',
        style: {
          width: 2,
          "line-color": "#78716c",
        },
      },
      {
        selector: 'edge[relType="same_file"]',
        style: {
          "line-style": "dashed",
          opacity: 0.3,
        },
      },
    ],
    layout: {
      name: "cose",
      animate: false,
      padding: 30,
      nodeRepulsion: 8000,
      idealEdgeLength: 120,
    },
    userZoomingEnabled: true,
    userPanningEnabled: true,
    boxSelectionEnabled: false,
  });

  attachTooltip(cy);

  cy.on("tap", "node", (e) => {
    const idx = e.target.data("findingIndex");
    if (idx !== undefined && onSelectFinding) {
      onSelectFinding(idx);
    }
  });

  cy.fit(undefined, 20);
}

function findRelation(a, b) {
  const aFn = a.graphContext?.enclosing_function;
  const bFn = b.graphContext?.enclosing_function;

  if (aFn && bFn && aFn === bFn) {
    return { type: "same_function" };
  }

  const aCallees = a.graphContext?.callees || [];
  const bCallees = b.graphContext?.callees || [];
  if ((aFn && bCallees.includes(aFn)) || (bFn && aCallees.includes(bFn))) {
    return { type: "caller_callee" };
  }

  if (a.path === b.path) {
    return { type: "same_file" };
  }

  return null;
}
