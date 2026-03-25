// frontend/js/results.js

import { classColor, classLabel, fmtConfidence, repoName, commitSha, parseFindings, groupByFile } from "./utils.js";
import { renderRelationshipMap } from "./graph.js";

let allFindings = [];
let activeFilter = "all";
let selectedIndex = -1;
let analysisResult = null;
let listenersInitialized = false;
let lastRepoUrl = "";
let traceData = [];

/**
 * One-time setup for filter tabs, export buttons, and document-level listeners.
 * Safe to call multiple times -- only attaches listeners once.
 */
function initListeners() {
  if (listenersInitialized) return;
  listenersInitialized = true;

  // Filter tabs
  document.querySelectorAll(".filter-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".filter-tab").forEach((t) => t.setAttribute("aria-selected", "false"));
      document.querySelector(".filter-tab.active").classList.remove("active");
      tab.classList.add("active");
      tab.setAttribute("aria-selected", "true");
      activeFilter = tab.dataset.filter;
      renderList();
    });
  });

  // Export toggle
  document.getElementById("export-btn").addEventListener("click", () => {
    document.getElementById("export-menu").classList.toggle("hidden");
  });
  document.getElementById("export-json").addEventListener("click", () => downloadJson());
  document.getElementById("export-md").addEventListener("click", () => copyMarkdown());
  document.getElementById("relationship-map-btn").addEventListener("click", () => {
    const section = document.getElementById("relationship-map-section");
    const btn = document.getElementById("relationship-map-btn");
    const isVisible = !section.classList.contains("hidden");

    if (isVisible) {
      section.classList.add("hidden");
      btn.setAttribute("aria-expanded", "false");
    } else {
      section.classList.remove("hidden");
      btn.setAttribute("aria-expanded", "true");
      renderRelationshipMap(
        document.getElementById("relationship-map-container"),
        allFindings,
        (idx) => {
          selectedIndex = idx;
          renderList();
          renderDetail(allFindings[idx]);
        },
      );
    }
  });

  // Trace panel toggle
  document.getElementById("trace-btn").addEventListener("click", () => {
    const section = document.getElementById("trace-section");
    const btn = document.getElementById("trace-btn");
    const isVisible = !section.classList.contains("hidden");

    if (isVisible) {
      section.classList.add("hidden");
      btn.setAttribute("aria-expanded", "false");
    } else {
      section.classList.remove("hidden");
      btn.setAttribute("aria-expanded", "true");
      const log = document.getElementById("trace-log");
      log.innerHTML = traceData.map((evt) => renderTraceEntryHTML(evt)).join("");
    }
  });

  // Close export on outside click
  document.addEventListener("click", (e) => {
    if (!e.target.closest(".export-dropdown")) {
      document.getElementById("export-menu").classList.add("hidden");
    }
  });
}

export function renderResults(result, repoUrl, trace = []) {
  analysisResult = result;
  lastRepoUrl = repoUrl;
  traceData = trace;
  const annotated = result.annotated_json;
  allFindings = parseFindings(annotated);

  initListeners();

  // Header
  document.getElementById("results-repo").textContent = repoName(repoUrl);
  document.getElementById("results-sha").textContent = commitSha(annotated);
  // Framework badge from SBOM
  const profileEl = document.getElementById("results-framework");
  if (profileEl && result.sbom_profile) {
    const p = result.sbom_profile;
    let badge = p.framework || p.language || "";
    if (p.dep_count) badge += ` · ${p.dep_count} deps`;
    if (!p.has_csrf_protection) badge += " · No CSRF";
    profileEl.textContent = badge;
    profileEl.classList.remove("hidden");
  }
  renderSummary();
  const relBtn = document.getElementById("relationship-map-btn");
  const relSection = document.getElementById("relationship-map-section");
  relBtn.setAttribute("aria-expanded", "false");
  if (allFindings.length >= 2) {
    relBtn.classList.remove("hidden");
  } else {
    relBtn.classList.add("hidden");
  }
  relSection.classList.add("hidden");

  // Trace button — show only if trace data exists
  const traceBtn = document.getElementById("trace-btn");
  const traceSection = document.getElementById("trace-section");
  traceBtn.setAttribute("aria-expanded", "false");
  if (traceData.length > 0) {
    traceBtn.classList.remove("hidden");
  } else {
    traceBtn.classList.add("hidden");
  }
  traceSection.classList.add("hidden");

  // Warnings
  const warningsBar = document.getElementById("warnings-bar");
  if (result.warnings && result.warnings.length > 0) {
    warningsBar.innerHTML = result.warnings
      .map((w) => `<div class="warning-item">${escapeHtml(w)}<button class="warning-dismiss" aria-label="Dismiss warning">&times;</button></div>`)
      .join("");
    warningsBar.classList.remove("hidden");

    // Dismiss handlers
    warningsBar.querySelectorAll(".warning-dismiss").forEach((btn) => {
      btn.addEventListener("click", () => {
        btn.parentElement.remove();
        if (!warningsBar.querySelector(".warning-item")) {
          warningsBar.classList.add("hidden");
        }
      });
    });
  } else {
    warningsBar.classList.add("hidden");
  }

  // Initial render
  activeFilter = "all";
  document.querySelector(".filter-tab.active")?.classList.remove("active");
  document.querySelector('.filter-tab[data-filter="all"]')?.classList.add("active");
  selectedIndex = -1;
  renderList();
  showEmptyDetail();
}

function renderSummary() {
  const counts = { true_positive: 0, false_positive: 0, uncertain: 0 };
  for (const f of allFindings) counts[f.classification]++;
  document.getElementById("results-summary").innerHTML =
    `<span style="color:#dc2626">${counts.true_positive} true</span> · ` +
    `<span style="color:#16a34a">${counts.false_positive} false</span> · ` +
    `<span style="color:#ca8a04">${counts.uncertain} uncertain</span>`;
}

function renderList() {
  const list = document.getElementById("findings-list");
  const filtered = activeFilter === "all"
    ? allFindings
    : allFindings.filter((f) => f.classification === activeFilter);

  const grouped = groupByFile(filtered);
  let html = "";

  for (const [path, findings] of grouped) {
    html += `<div class="file-group">`;
    html += `<button class="file-group-header" aria-expanded="true">`;
    html += `<span class="file-group-arrow">&#9662;</span>`;
    html += `<span class="file-group-path">${escapeHtml(path)}</span>`;
    html += `<span class="file-group-count">${findings.length}</span>`;
    html += `</button>`;
    html += `<div class="file-group-items">`;
    for (const f of findings) {
      const idx = allFindings.indexOf(f);
      const selected = idx === selectedIndex ? " selected" : "";
      html += `<button class="finding-item${selected}" data-index="${idx}" style="border-left-color:${classColor(f.classification)}">`;
      html += `<span class="finding-rule">${escapeHtml(f.rule)}</span>`;
      html += `<span class="finding-meta">${escapeHtml(f.path)}:${f.line} · ${fmtConfidence(f.confidence)}</span>`;
      html += `</button>`;
    }
    html += `</div></div>`;
  }

  if (!html) html = `<p class="findings-empty">No findings match this filter.</p>`;
  list.innerHTML = html;

  // File group toggle handlers
  list.querySelectorAll(".file-group-header").forEach((header) => {
    header.addEventListener("click", () => {
      const group = header.parentElement;
      group.classList.toggle("collapsed");
      header.setAttribute("aria-expanded", !group.classList.contains("collapsed"));
    });
  });

  // Finding click handlers
  list.querySelectorAll(".finding-item").forEach((el) => {
    el.addEventListener("click", () => {
      selectedIndex = parseInt(el.dataset.index, 10);
      list.querySelectorAll(".finding-item").forEach((e) => e.classList.remove("selected"));
      el.classList.add("selected");
      renderDetail(allFindings[selectedIndex]);
    });
  });
}

function renderDetail(f) {
  document.getElementById("detail-empty").classList.add("hidden");
  const content = document.getElementById("detail-content");
  content.classList.remove("hidden");

  let html = "";
  html += `<div class="detail-header">`;
  html += `<h3 class="detail-rule">${escapeHtml(f.rule)}</h3>`;
  html += `<span class="verdict-badge" style="background:${classColor(f.classification)}">${classLabel(f.classification)}</span>`;
  html += `</div>`;

  html += `<div class="detail-confidence">`;
  html += `<span class="detail-label">Confidence</span>`;
  html += `<div class="confidence-bar"><div class="confidence-fill" style="width:${Math.round(f.confidence * 100)}%;background:${classColor(f.classification)}"></div></div>`;
  html += `<span class="confidence-value">${fmtConfidence(f.confidence)}</span>`;
  html += `</div>`;

  html += `<div class="detail-location">`;
  html += `<span class="detail-label">Location</span>`;
  html += `<span>${escapeHtml(f.path)}:${f.line}</span>`;
  html += `</div>`;

  if (f.message) {
    html += `<div class="detail-section">`;
    html += `<span class="detail-label">Message</span>`;
    html += `<p>${escapeHtml(f.message)}</p>`;
    html += `</div>`;
  }

  html += `<div class="detail-section">`;
  html += `<span class="detail-label">Reasoning</span>`;
  html += formatReasoning(f.reasoning);
  html += `</div>`;

  if (f.lines) {
    html += `<div class="detail-section">`;
    html += `<span class="detail-label">Code</span>`;
    html += `<pre class="code-block">${escapeHtml(f.lines)}</pre>`;
    html += `</div>`;
  }

  if (f.remediationExplanation) {
    html += `<div class="detail-section">`;
    html += `<span class="detail-label">Remediation</span>`;
    html += `<p>${escapeHtml(f.remediationExplanation)}</p>`;
    if (f.remediationCode) {
      html += `<pre class="code-block">${escapeHtml(f.remediationCode)}</pre>`;
    }
    html += `</div>`;
  }

  // Enrichment context panel (replaces old dataflow section)
  html += renderEnrichmentPanel(f);

  // Data flow (replaces call graph)
  html += `<div class="detail-section">`;
  html += `<span class="detail-label">Data Flow</span>`;
  html += renderDataFlow(f);
  html += `</div>`;

  content.innerHTML = html;

  // Wire enrichment panel interactions
  wireEnrichmentPanel();
}

const SOURCE_LABELS = { joern: "Joern CPG", gkg: "gkg", tree_sitter: "tree-sitter" };
const MAX_DISPLAY_ROWS = 20;

function renderEnrichmentPanel(f) {
  const gc = f.graphContext;
  if (!gc) return "";
  const hasCallers = gc.callers && gc.callers.length > 0;
  const hasCallees = gc.callees && gc.callees.length > 0;
  const hasTaint = f.taintReachable !== null;
  const hasImports = gc.imports && gc.imports.length > 0;
  if (!hasCallers && !hasCallees && !hasTaint && !hasImports) return "";

  let html = `<div class="enrichment-panel">`;

  // Header
  const srcLabel = SOURCE_LABELS[gc.source] || gc.source || "unknown";
  const fn = gc.enclosing_function || "";
  html += `<div class="enrich-header">`;
  html += `<span style="color:var(--text-secondary)">Source:</span>`;
  html += `<span class="enrich-source-badge">${escapeHtml(srcLabel)}</span>`;
  if (fn) {
    html += `<span style="color:var(--text-secondary)">Function:</span>`;
    html += `<span>${escapeHtml(fn)}()</span>`;
  }
  html += `<span style="color:var(--text-secondary)">at</span>`;
  html += `<span style="color:var(--primary)">${escapeHtml(f.path)}:${f.line}</span>`;
  html += `</div>`;

  // Tabs — order: Callers > Taint > Callees > Imports (spec: Callers first, then Taint, then rest)
  const tabs = [];
  if (hasCallers) tabs.push({ id: "callers", label: `Callers (${gc.callers.length})` });
  if (hasTaint) tabs.push({ id: "taint", label: "Taint Path" });
  if (hasCallees) tabs.push({ id: "callees", label: `Callees (${gc.callees.length})` });
  if (hasImports) tabs.push({ id: "imports", label: `Imports (${gc.imports.length})` });

  const defaultTab = tabs[0]?.id || "";
  html += `<div class="enrich-tabs" role="tablist">`;
  tabs.forEach((t) => {
    const isActive = t.id === defaultTab;
    html += `<div class="enrich-tab${isActive ? " active" : ""}" role="tab" tabindex="0" aria-selected="${isActive ? "true" : "false"}" data-enrich-tab="${t.id}">${t.label}</div>`;
  });
  html += `</div>`;

  // Panels
  // Callers
  if (hasCallers) {
    html += `<div class="enrich-panel-body" data-enrich-panel="callers"${defaultTab !== "callers" ? ' style="display:none"' : ""}>`;
    html += `<table class="enrich-table"><thead><tr>`;
    html += `<th style="width:28px"></th><th style="width:42%">File</th><th style="width:60px">Line</th><th>Function</th>`;
    html += `</tr></thead><tbody>`;
    const shown = gc.callers.slice(0, MAX_DISPLAY_ROWS);
    shown.forEach((c) => {
      const hasCtx = c.context && c.context.trim().length > 0;
      html += `<tr class="enrich-row"${hasCtx ? ' aria-expanded="false"' : ' style="cursor:default"'}>`;
      html += `<td>${hasCtx ? '<span class="enrich-arrow">&#9654;</span>' : ""}</td>`;
      html += `<td style="color:var(--primary)">${escapeHtml(c.file)}</td>`;
      html += `<td>${c.line}</td>`;
      html += `<td>${escapeHtml(c.function)}()</td>`;
      html += `</tr>`;
      if (hasCtx) {
        html += `<tr class="enrich-code"><td colspan="4"><div class="enrich-code-inner">`;
        html += renderCodeBlock(c.context, c.line);
        html += `</div></td></tr>`;
      }
    });
    html += `</tbody></table>`;
    if (gc.callers.length > MAX_DISPLAY_ROWS) {
      html += `<div class="enrich-more">+${gc.callers.length - MAX_DISPLAY_ROWS} more callers</div>`;
    }
    html += `</div>`;
  }

  // Callees (pill layout)
  if (hasCallees) {
    html += `<div class="enrich-panel-body" data-enrich-panel="callees"${defaultTab !== "callees" ? ' style="display:none"' : ""}>`;
    html += `<div class="enrich-pills">`;
    const shown = gc.callees.slice(0, MAX_DISPLAY_ROWS);
    shown.forEach((name) => {
      html += `<span class="enrich-pill">${escapeHtml(name)}()</span>`;
    });
    if (gc.callees.length > MAX_DISPLAY_ROWS) {
      html += `<span class="enrich-pill" style="color:var(--text-secondary);font-style:italic">+${gc.callees.length - MAX_DISPLAY_ROWS} more</span>`;
    }
    html += `</div></div>`;
  }

  // Taint
  if (hasTaint) {
    html += `<div class="enrich-panel-body" data-enrich-panel="taint"${defaultTab !== "taint" ? ' style="display:none"' : ""}>`;
    html += `<div class="enrich-taint">`;
    let dotColor, text;
    if (!f.taintReachable) {
      dotColor = "var(--success, #16a34a)";
      text = "No untrusted data reaches this sink";
    } else if (f.taintSanitized) {
      dotColor = "var(--warning, #ca8a04)";
      text = `Input reaches sink, sanitized via ${(f.taintSanitizers || []).join(", ") || "unknown"}`;
    } else {
      dotColor = "var(--danger, #dc2626)";
      text = "Untrusted input reaches sink without sanitization";
    }
    html += `<div class="enrich-taint-verdict"><span class="enrich-taint-dot" style="background:${dotColor}"></span>${escapeHtml(text)}</div>`;
    if (f.taintPath && f.taintPath.length > 0) {
      html += `<ol style="margin:0;padding-left:20px;font-size:13px;font-family:monospace;color:var(--text-secondary)">`;
      f.taintPath.slice(0, 10).forEach((step) => {
        html += `<li style="margin-bottom:4px">${escapeHtml(step)}</li>`;
      });
      if (f.taintPath.length > 10) {
        html += `<li style="color:var(--text-tertiary);font-style:italic">+${f.taintPath.length - 10} more steps</li>`;
      }
      html += `</ol>`;
    }
    if (f.taintSanitizers && f.taintSanitizers.length > 0) {
      html += `<div style="margin-top:8px;font-size:12px;color:var(--text-secondary)">Sanitizers: ${f.taintSanitizers.map((s) => escapeHtml(s)).join(", ")}</div>`;
    }
    html += `</div></div>`;
  }

  // Imports (pill layout)
  if (hasImports) {
    html += `<div class="enrich-panel-body" data-enrich-panel="imports"${defaultTab !== "imports" ? ' style="display:none"' : ""}>`;
    html += `<div class="enrich-pills">`;
    gc.imports.forEach((imp) => {
      html += `<span class="enrich-pill">${escapeHtml(imp)}</span>`;
    });
    html += `</div></div>`;
  }

  html += `</div>`;
  return html;
}

function renderCodeBlock(code, highlightLine) {
  const rawLines = code.split("\n");
  const numbered = /^\s*\d+\s*[|│]/.test(rawLines[0] || "");
  const parsed = [];
  rawLines.forEach((line, i) => {
    if (!line && i === rawLines.length - 1) return;
    let ln, src;
    if (numbered) {
      const m = line.match(/^\s*(\d+)\s*[|│]\s?(.*)/);
      if (m) { ln = parseInt(m[1], 10); src = m[2]; }
      else { ln = ""; src = line; }
    } else {
      ln = i + 1;
      src = line;
    }
    parsed.push({ ln, src });
  });

  // Window to ±10 lines around the highlight line
  const WINDOW = 10;
  let startIdx = 0;
  let endIdx = parsed.length;
  if (parsed.length > WINDOW * 2 + 1) {
    const hlIdx = parsed.findIndex((p) => p.ln === highlightLine);
    if (hlIdx >= 0) {
      startIdx = Math.max(0, hlIdx - WINDOW);
      endIdx = Math.min(parsed.length, hlIdx + WINDOW + 1);
    } else {
      endIdx = WINDOW * 2 + 1;
    }
  }

  let html = "";
  parsed.slice(startIdx, endIdx).forEach((p) => {
    const isHl = p.ln === highlightLine;
    html += `<div class="enrich-code-line${isHl ? " enrich-code-hl" : ""}">`;
    html += `<span class="enrich-code-ln">${p.ln}</span>`;
    html += `<span class="enrich-code-src">${escapeHtml(p.src)}</span>`;
    html += `</div>`;
  });
  return html;
}

function wireEnrichmentPanel() {
  // Tab switching
  function activateEnrichTab(tab) {
    const panel = tab.closest(".enrichment-panel");
    panel.querySelectorAll(".enrich-tab").forEach((t) => {
      t.classList.remove("active");
      t.setAttribute("aria-selected", "false");
    });
    tab.classList.add("active");
    tab.setAttribute("aria-selected", "true");
    const target = tab.dataset.enrichTab;
    panel.querySelectorAll(".enrich-panel-body").forEach((p) => {
      p.style.display = p.dataset.enrichPanel === target ? "" : "none";
    });
  }

  document.querySelectorAll(".enrich-tab").forEach((tab) => {
    tab.addEventListener("click", () => activateEnrichTab(tab));
    tab.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        activateEnrichTab(tab);
      }
    });
  });

  // Expandable rows
  document.querySelectorAll(".enrich-row").forEach((row) => {
    const codeRow = row.nextElementSibling;
    if (!codeRow || !codeRow.classList.contains("enrich-code")) return;
    row.addEventListener("click", () => {
      const arrow = row.querySelector(".enrich-arrow");
      const isOpen = codeRow.style.display === "table-row";
      codeRow.style.display = isOpen ? "none" : "table-row";
      row.setAttribute("aria-expanded", isOpen ? "false" : "true");
      if (arrow) arrow.style.transform = isOpen ? "" : "rotate(90deg)";
    });
  });
}

const FLOW_COLORS = {
  source: "#16a34a",
  propagation: "#f59e0b",
  sink: "#dc2626",
  caller: "#3b82f6",
  finding: "#dc2626",
  calls: "#78716c",
  sanitizer: "#22c55e",
};

function renderDataFlow(f) {
  const gc = f.graphContext;
  const hasTaint = f.taintPath && f.taintPath.length > 0;
  const hasCallers = gc && gc.callers && gc.callers.length > 0;

  if (hasTaint) {
    return renderTaintFlow(f);
  } else if (hasCallers || (gc && gc.callees && gc.callees.length > 0)) {
    return renderCallerFlow(f);
  }
  return `<div class="dataflow-empty">No data flow information available</div>`;
}

function renderTaintFlow(f) {
  let steps = f.taintPath;

  // Compress long paths: first 3 + "... N more" + last 3
  let compressed = false;
  let hiddenCount = 0;
  if (steps.length > 8) {
    hiddenCount = steps.length - 6;
    steps = [...steps.slice(0, 3), null, ...steps.slice(-3)];
    compressed = true;
  }

  let html = `<div class="dataflow-steps">`;

  steps.forEach((step, i) => {
    const isFirst = i === 0;
    const isLast = i === steps.length - 1;
    const isPlaceholder = step === null;

    if (isPlaceholder) {
      // "... N more steps" connector
      html += `<div class="dataflow-step">`;
      html += `<div class="dataflow-step-marker">`;
      html += `<div style="width:26px;height:26px;display:flex;align-items:center;justify-content:center;color:var(--text-secondary);font-size:16px;">⋮</div>`;
      html += `<div class="dataflow-connector"></div>`;
      html += `</div>`;
      html += `<div class="dataflow-step-body" style="display:flex;align-items:center;">`;
      html += `<span style="color:var(--text-secondary);font-size:12px;font-style:italic;">${hiddenCount} more steps</span>`;
      html += `</div></div>`;
      return;
    }

    // Parse step: "file.ts:42:functionName" or just a string
    const parts = step.split(":");
    let file = "", line = "", func = "";
    if (parts.length >= 3) {
      file = parts.slice(0, -2).join(":");
      line = parts[parts.length - 2];
      func = parts[parts.length - 1];
    } else if (parts.length === 2) {
      file = parts[0];
      line = parts[1];
    } else {
      func = step;
    }

    let label, color;
    if (isFirst) {
      label = "SOURCE";
      color = FLOW_COLORS.source;
    } else if (isLast) {
      label = "SINK";
      color = FLOW_COLORS.sink;
    } else {
      label = "PROPAGATION";
      color = FLOW_COLORS.propagation;
    }

    // Check for sanitizer
    if (f.taintSanitized && f.taintSanitizers && f.taintSanitizers.some((s) => step.includes(s))) {
      label = "SANITIZER";
      color = FLOW_COLORS.sanitizer;
    }

    const num = compressed ? "" : (i + 1);
    const location = [file, line ? `:${line}` : "", func ? ` · ${func}()` : ""].filter(Boolean).join("");

    html += `<div class="dataflow-step">`;
    html += `<div class="dataflow-step-marker">`;
    html += `<div class="dataflow-step-circle" style="background:${color}">${num || "·"}</div>`;
    if (!isLast) html += `<div class="dataflow-connector"></div>`;
    html += `</div>`;
    html += `<div class="dataflow-step-body">`;
    html += `<div class="dataflow-step-label" style="color:${color}">${label}</div>`;
    if (location) {
      html += `<div class="dataflow-step-location">${escapeHtml(location)}</div>`;
    }
    // Code snippet: for sink use finding's code, for source show the taint path entry
    if (isLast && f.lines) {
      html += `<div class="dataflow-step-code" style="border-left-color:${color}">${escapeHtml(f.lines)}</div>`;
    } else if (isFirst && step) {
      html += `<div class="dataflow-step-code" style="border-left-color:${color}">${escapeHtml(step)}</div>`;
    }
    html += `</div></div>`;
  });

  // Taint verdict summary at the bottom
  if (f.taintSanitized) {
    html += `<div style="margin-top:8px;font-size:12px;color:var(--text-secondary)">`;
    html += `Sanitized via: ${(f.taintSanitizers || []).map((s) => escapeHtml(s)).join(", ")}`;
    html += `</div>`;
  }

  html += `</div>`;
  return html;
}

function renderCallerFlow(f) {
  const gc = f.graphContext || {};
  const callers = gc.callers || [];
  const callees = gc.callees || [];

  let html = `<div class="dataflow-steps">`;

  // Step 1: Caller (if any)
  if (callers.length > 0) {
    const c = callers[0];
    html += `<div class="dataflow-step">`;
    html += `<div class="dataflow-step-marker">`;
    html += `<div class="dataflow-step-circle" style="background:${FLOW_COLORS.caller}">1</div>`;
    html += `<div class="dataflow-connector"></div>`;
    html += `</div>`;
    html += `<div class="dataflow-step-body">`;
    html += `<div class="dataflow-step-label" style="color:${FLOW_COLORS.caller}">CALLER</div>`;
    html += `<div class="dataflow-step-location">${escapeHtml(c.file)}:${c.line} · ${escapeHtml(c.function)}()</div>`;
    if (callers.length > 1) {
      html += `<div style="font-size:11px;color:var(--text-secondary);margin-top:2px">+${callers.length - 1} more callers (see Callers tab)</div>`;
    }
    html += `</div></div>`;
  }

  // Step 2: The finding itself
  const fnName = gc.enclosing_function || "unknown";
  html += `<div class="dataflow-step">`;
  html += `<div class="dataflow-step-marker">`;
  html += `<div class="dataflow-step-circle" style="background:${FLOW_COLORS.finding}">${callers.length > 0 ? "2" : "1"}</div>`;
  if (callees.length > 0) html += `<div class="dataflow-connector"></div>`;
  html += `</div>`;
  html += `<div class="dataflow-step-body">`;
  html += `<div class="dataflow-step-label" style="color:${FLOW_COLORS.finding}">FINDING</div>`;
  html += `<div class="dataflow-step-location">${escapeHtml(f.path)}:${f.line} · ${escapeHtml(fnName)}()</div>`;
  if (f.lines) {
    html += `<div class="dataflow-step-code" style="border-left-color:${FLOW_COLORS.finding}">${escapeHtml(f.lines)}</div>`;
  }
  html += `</div></div>`;

  // Step 3: Callees (if any)
  if (callees.length > 0) {
    const shown = callees.slice(0, 8);
    const more = callees.length > 8 ? ` +${callees.length - 8} more` : "";
    const num = callers.length > 0 ? "3" : "2";
    html += `<div class="dataflow-step">`;
    html += `<div class="dataflow-step-marker">`;
    html += `<div class="dataflow-step-circle" style="background:${FLOW_COLORS.calls}">${num}</div>`;
    html += `</div>`;
    html += `<div class="dataflow-step-body">`;
    html += `<div class="dataflow-step-label" style="color:${FLOW_COLORS.calls}">CALLS</div>`;
    html += `<div class="dataflow-step-callees">${shown.map((c) => escapeHtml(c) + "()").join(", ")}${more}</div>`;
    html += `</div></div>`;
  }

  html += `</div>`;
  return html;
}

const REASONING_SECTIONS = ["SOURCE", "SANITIZATION", "SINK", "EXPLOITABILITY"];
const REASONING_COLORS = { SOURCE: "#3b82f6", SANITIZATION: "#22c55e", SINK: "#f59e0b", EXPLOITABILITY: "#dc2626" };

function formatReasoning(reasoning) {
  if (!reasoning) return `<p>No reasoning provided.</p>`;

  // Try to parse structured format: "SOURCE: ... | SANITIZATION: ... | SINK: ... | EXPLOITABILITY: ..."
  const parts = reasoning.split(/\s*\|\s*/);
  const parsed = {};
  for (const part of parts) {
    for (const section of REASONING_SECTIONS) {
      if (part.toUpperCase().startsWith(section + ":")) {
        parsed[section] = part.slice(section.length + 1).trim();
        break;
      }
    }
  }

  // If we found at least 3 of 4 sections, render structured
  if (Object.keys(parsed).length >= 3) {
    let html = `<div class="reasoning-structured">`;
    for (const section of REASONING_SECTIONS) {
      if (!parsed[section]) continue;
      const color = REASONING_COLORS[section];
      html += `<div class="reasoning-item">`;
      html += `<span class="reasoning-label" style="color:${color}">${section}</span>`;
      html += `<span class="reasoning-text">${escapeHtml(parsed[section])}</span>`;
      html += `</div>`;
    }
    html += `</div>`;
    return html;
  }

  // Fallback: render as plain text (for old/non-structured responses)
  return `<p>${escapeHtml(reasoning)}</p>`;
}

function showEmptyDetail() {
  document.getElementById("detail-empty").classList.remove("hidden");
  document.getElementById("detail-content").classList.add("hidden");
}

function downloadJson() {
  if (!analysisResult) return;
  const name = repoName(lastRepoUrl).replace(/\//g, "-");
  const blob = new Blob([JSON.stringify(analysisResult.annotated_json, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `${name}-analysis.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function copyMarkdown() {
  if (!analysisResult?.markdown_summary) return;
  navigator.clipboard.writeText(analysisResult.markdown_summary);
}

const STEP_LABELS = {
  repo_clone: "Clone repository",
  gkg_check: "Check graph tools",
  gkg_index: "Index call graph",
  gkg_server: "Start graph server",
  repo_map: "Fetch repo map",
  joern_check: "Check Joern CPG",
  joern_cpg: "Generate code graph",
  enrich: "Enrich findings",
  llm_call: "LLM analysis",
  parse_results: "Parse results",
  sbom_generate: "Analyze dependencies",
};

function renderTraceEntryHTML(event) {
  const icons = { completed: "\u2713", error: "\u2717", skipped: "\u2014", in_progress: "\u27F3" };
  const icon = icons[event.status] || "?";
  const label = STEP_LABELS[event.step] || event.step;
  const ms = event.duration_ms;
  const duration = ms == null ? "" : ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`;
  const detail = escapeHtml(event.detail || "");
  return `<div class="trace-entry ${event.status}">` +
    `<span class="trace-icon ${event.status}">${icon}</span>` +
    `<span class="trace-label">${label}</span>` +
    `<span class="trace-duration">${duration}</span>` +
    `<span class="trace-detail">${detail}</span>` +
    `</div>`;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str || "";
  return div.innerHTML;
}
