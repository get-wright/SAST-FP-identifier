# Frontend Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the vanilla JS frontend with a Vite + Preact SPA featuring a three-panel results layout, step wizard setup, and dense dark-first design.

**Architecture:** Hash-routed SPA with three pages (Setup wizard, Analyzing progress, Results three-panel). Preact Signals for state management. CSS Modules for scoped styles. Same backend API — only the static file mount path changes.

**Tech Stack:** Vite, Preact 10, preact-router, @preact/signals, highlight.js (core), CSS Modules

**Spec:** `docs/superpowers/specs/2026-03-26-frontend-redesign-design.md`

---

## File Map

### New files (frontend/src/)
| File | Responsibility |
|------|---------------|
| `frontend/index.html` | Vite entry shell |
| `frontend/vite.config.js` | Vite config with Preact plugin |
| `frontend/package.json` | Dependencies |
| `frontend/src/main.jsx` | Mount `<App />` |
| `frontend/src/app.jsx` | Hash router |
| `frontend/src/stores/settings.js` | Server API key + LLM config (localStorage-backed signals) |
| `frontend/src/stores/analysis.js` | Findings, filters, selectedFingerprint, result (memory-only signals) |
| `frontend/src/lib/api.js` | `analyzeStream()` SSE handler |
| `frontend/src/lib/utils.js` | classify, classColor, classLabel, fmtConfidence, escapeHtml, parseFindings, groupByFile |
| `frontend/src/styles/theme.css` | CSS custom properties (dark + light) |
| `frontend/src/styles/global.css` | Reset, typography, base |
| `frontend/src/pages/Setup.jsx` | Step wizard container |
| `frontend/src/pages/Analyzing.jsx` | Pipeline progress page |
| `frontend/src/pages/Results.jsx` | Three-panel layout shell |
| `frontend/src/components/SetupWizard/StepUpload.jsx` | File upload step |
| `frontend/src/components/SetupWizard/StepRepo.jsx` | Repo URL step |
| `frontend/src/components/SetupWizard/StepLLM.jsx` | LLM provider step |
| `frontend/src/components/ProgressTrace.jsx` | Pipeline step rows |
| `frontend/src/components/FilterSidebar.jsx` | Filter facets panel |
| `frontend/src/components/FindingsList.jsx` | File-grouped findings list |
| `frontend/src/components/DetailPanel.jsx` | Tabbed detail panel |
| `frontend/src/components/CodeBlock.jsx` | Syntax-highlighted code viewer |
| `frontend/src/components/DataflowView.jsx` | Taint/caller flow visualization |
| `frontend/src/components/EnrichmentView.jsx` | Callers, callees, imports, taint |

### Modified files
| File | Change |
|------|--------|
| `src/api/app.py` | Change `frontend_dir` assignment to point at `frontend/dist` |
| `Dockerfile` | Add `npm install && npm run build` step after `COPY frontend/ frontend/` |

### Deleted files
| File | Reason |
|------|--------|
| `frontend/js/app.js` | Replaced by Preact app |
| `frontend/js/results.js` | Split into components |
| `frontend/js/upload.js` | Replaced by SetupWizard |
| `frontend/js/utils.js` | Migrated to src/lib/utils.js |
| `frontend/js/api.js` | Migrated to src/lib/api.js |
| `frontend/js/graph.js` | Cytoscape removed |
| `frontend/css/style.css` | Replaced by theme.css + CSS Modules |

---

### Task 1: Vite + Preact scaffold

**Files:**
- Create: `frontend/package.json`
- Create: `frontend/vite.config.js`
- Create: `frontend/index.html`
- Create: `frontend/src/main.jsx`
- Create: `frontend/src/app.jsx`
- Create: `frontend/src/styles/theme.css`
- Create: `frontend/src/styles/global.css`

- [ ] **Step 1: Create package.json**

```json
{
  "name": "semgrep-analyzer-frontend",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "preact": "^10.25.0",
    "preact-router": "^4.1.2",
    "@preact/signals": "^2.0.0",
    "highlight.js": "^11.11.0"
  },
  "devDependencies": {
    "@preact/preset-vite": "^2.9.0",
    "vite": "^6.0.0"
  }
}
```

- [ ] **Step 2: Create vite.config.js**

```js
import { defineConfig } from "vite";
import preact from "@preact/preset-vite";

export default defineConfig({
  plugins: [preact()],
  root: ".",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  css: {
    modules: {
      localsConvention: "camelCase",
    },
  },
});
```

- [ ] **Step 3: Create index.html (Vite entry)**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Semgrep Analyzer</title>
</head>
<body>
  <div id="app"></div>
  <script type="module" src="/src/main.jsx"></script>
</body>
</html>
```

- [ ] **Step 4: Create theme.css with dark/light CSS custom properties**

Full dark theme vars (--bg: #0d1117, --panel: #161b22, --surface: #1f2937, etc.), light theme vars, `@media (prefers-color-scheme: dark)` auto-detection, `[data-theme="dark"]` and `[data-theme="light"]` manual overrides. See spec "Visual Design System" section for all values.

- [ ] **Step 5: Create global.css with reset and typography**

Box-sizing reset, body styling (`background: var(--bg); color: var(--text); font-family: system stack`), monospace font-family variable, base link/button resets, `tabular-nums` utility class, `overflow-x: hidden` on html. Reduced motion media query wrapping transitions.

- [ ] **Step 6: Create main.jsx**

```jsx
import { render } from "preact";
import { App } from "./app";
import "./styles/theme.css";
import "./styles/global.css";

render(<App />, document.getElementById("app"));
```

- [ ] **Step 7: Create app.jsx with hash router**

```jsx
import { LocationProvider, Router, Route } from "preact-iso";
import { Setup } from "./pages/Setup";
import { Analyzing } from "./pages/Analyzing";
import { Results } from "./pages/Results";

export function App() {
  return (
    <LocationProvider>
      <Router>
        <Route path="/" component={Setup} />
        <Route path="/analyzing" component={Analyzing} />
        <Route path="/results" component={Results} />
      </Router>
    </LocationProvider>
  );
}
```

Note: Use `preact-iso` (included with `@preact/preset-vite`) which provides `LocationProvider`, `Router`, `Route`, and `useLocation` for programmatic navigation. For hash-based routing, configure `LocationProvider` or use the `?hash` query approach. At implementation time, verify `preact-iso` hash routing support — if not available, use `preact-router` with `<Router>` which reads `window.location` directly. The implementer should test both and pick whichever works for hash-based URLs.

- [ ] **Step 8: Add frontend build artifacts to .gitignore**

Append to `.gitignore`:
```
frontend/node_modules/
frontend/dist/
```

- [ ] **Step 9: Install dependencies and verify dev server starts**

```bash
cd frontend && npm install && npm run dev
```

Expected: Vite dev server starts, shows blank page at `http://localhost:5173`.

- [ ] **Step 10: Commit**

```bash
git add frontend/package.json frontend/vite.config.js frontend/index.html frontend/src/ .gitignore
git commit -m "feat(frontend): scaffold Vite + Preact project with router and theme"
```

---

### Task 2: Stores (settings + analysis)

**Files:**
- Create: `frontend/src/stores/settings.js`
- Create: `frontend/src/stores/analysis.js`
- Create: `frontend/src/lib/utils.js`

- [ ] **Step 1: Create lib/utils.js**

Migrate and clean up from old `frontend/js/utils.js`. Functions needed:

```js
const FP_THRESHOLD = 0.8;

export function classify(analysis) {
  if (!analysis || analysis.confidence < FP_THRESHOLD) return "uncertain";
  return analysis.verdict || "uncertain";
}

export function classColor(cls) {
  return { true_positive: "#ef4444", false_positive: "#22c55e", uncertain: "#eab308" }[cls] || "#6b7280";
}

export function classLabel(cls) {
  return { true_positive: "True Positive", false_positive: "False Positive", uncertain: "Uncertain" }[cls] || "Unknown";
}

export function fmtConfidence(val) {
  return `${Math.round((val || 0) * 100)}%`;
}

export function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str || "";
  return div.innerHTML;
}

export function repoName(url) {
  try {
    const path = new URL(url).pathname.replace(/\.git$/, "").replace(/\/$/, "");
    const parts = path.split("/").filter(Boolean);
    return parts.length >= 2 ? `${parts[parts.length - 2]}/${parts[parts.length - 1]}` : parts[parts.length - 1] || url;
  } catch { return url; }
}

export function commitSha(annotatedJson) {
  const results = annotatedJson?.results || [];
  if (results.length === 0) return "unknown";
  const sha = results[0]?.extra?.x_fp_analysis?.commit_sha || "";
  return sha.slice(0, 7) || "unknown";
}

export function parseFindings(annotatedJson) {
  return (annotatedJson?.results || []).map((r) => {
    const a = r.extra?.x_fp_analysis || {};
    const cls = classify(a);
    return {
      path: r.path || "",
      line: r.start?.line || 0,
      rule: r.check_id || "",
      message: r.extra?.message || "",
      severity: r.extra?.severity || "INFO",
      fingerprint: r.extra?.fingerprint || "",
      classification: cls,
      confidence: a.confidence || 0,
      reasoning: a.reasoning || "",
      dataflowAnalysis: a.dataflow_analysis || "",
      verdict: a.verdict || "uncertain",
      status: a.status || "ok",
      decisionSource: a.decision_source || "none",
      appliedMemoryIds: a.applied_memory_ids || [],
      overrideId: a.override_id || null,
      remediationCode: a.remediation_code || null,
      remediationExplanation: a.remediation_explanation || null,
      lines: r.extra?.lines || "",
      graphContext: a.graph_context || null,
    };
  });
}

export function groupByFile(findings) {
  const map = new Map();
  for (const f of findings) {
    if (!map.has(f.path)) map.set(f.path, []);
    map.get(f.path).push(f);
  }
  return map;
}
```

- [ ] **Step 2: Create stores/settings.js**

```js
import { signal, effect } from "@preact/signals";

function loadJSON(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

export const serverApiKey = signal(localStorage.getItem("semgrep_api_key") || "");
export const serverKeyError = signal(false);

export const llmConfig = signal(loadJSON("llm_config", {
  provider: "",
  apiKey: "",
  model: "",
  baseUrl: "",
  isReasoningModel: false,
}));

export const lastRepoUrl = signal(localStorage.getItem("last_repo_url") || "");

// Auto-persist on change
effect(() => localStorage.setItem("semgrep_api_key", serverApiKey.value));
effect(() => localStorage.setItem("llm_config", JSON.stringify(llmConfig.value)));
effect(() => localStorage.setItem("last_repo_url", lastRepoUrl.value));
```

- [ ] **Step 3: Create stores/analysis.js**

```js
import { signal, computed } from "@preact/signals";
import { parseFindings, groupByFile } from "../lib/utils";

export const rawResult = signal(null);
export const repoUrl = signal("");
export const traceEvents = signal([]);
export const selectedFingerprint = signal(null); // finding.fingerprint or null
export const activeTab = signal("analysis");

export const filters = signal({
  verdicts: [],    // empty = all
  files: [],       // empty = all
  severities: [],  // empty = all
  minConfidence: 0,
  maxConfidence: 100,
});

export const allFindings = computed(() => {
  if (!rawResult.value) return [];
  return parseFindings(rawResult.value.annotated_json);
});

export const filteredFindings = computed(() => {
  const f = filters.value;
  return allFindings.value.filter((finding) => {
    if (f.verdicts.length && !f.verdicts.includes(finding.classification)) return false;
    if (f.files.length && !f.files.includes(finding.path)) return false;
    if (f.severities.length && !f.severities.includes(finding.severity)) return false;
    const confPct = Math.round(finding.confidence * 100);
    if (confPct < f.minConfidence || confPct > f.maxConfidence) return false;
    return true;
  });
});

export const groupedFindings = computed(() => groupByFile(filteredFindings.value));

export const selectedFinding = computed(() => {
  const fp = selectedFingerprint.value;
  if (!fp) return null;
  return allFindings.value.find((f) => f.fingerprint === fp) || null;
});

export const counts = computed(() => {
  const c = { true_positive: 0, false_positive: 0, uncertain: 0 };
  for (const f of allFindings.value) c[f.classification]++;
  return c;
});

export function resetAnalysis() {
  rawResult.value = null;
  repoUrl.value = "";
  traceEvents.value = [];
  selectedFingerprint.value = null;
  activeTab.value = "analysis";
  filters.value = { verdicts: [], files: [], severities: [], minConfidence: 0, maxConfidence: 100 };
}
```

- [ ] **Step 4: Verify imports resolve**

```bash
cd frontend && npm run dev
```

Open browser console — no import errors.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/stores/ frontend/src/lib/utils.js
git commit -m "feat(frontend): add signal stores and utility functions"
```

---

### Task 3: SSE API client (lib/api.js)

**Files:**
- Create: `frontend/src/lib/api.js`

- [ ] **Step 1: Create lib/api.js**

Port from old `frontend/js/api.js` with the SSE discrimination logic from the spec:

```js
// baseUrl defaults to "" (same-origin, since backend serves the frontend).
// Only override for dev mode pointing at a different backend.
export async function analyzeStream(apiKey, repoUrl, semgrepJson, { onProgress, onResult, onError, onTrace, gitToken, llmOverride, baseUrl = "" }) {
  const body = { repo_url: repoUrl, semgrep_json: semgrepJson };
  if (gitToken) body.git_token = gitToken;
  if (llmOverride) body.llm_override = llmOverride;

  let response;
  try {
    response = await fetch(`${baseUrl}/analyze/stream`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
      body: JSON.stringify(body),
    });
  } catch (err) {
    onError(`Network error: ${err.message}`);
    return;
  }

  if (response.status === 401) {
    onError("__401__");
    return;
  }
  if (!response.ok) {
    const text = await response.text();
    onError(`Server error (${response.status}): ${text}`);
    return;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n\n");
      buffer = lines.pop();
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("data: ")) continue;
        try {
          const data = JSON.parse(trimmed.slice(6));
          if (data.result) onResult(data.result);
          else if (data.status === "error" && !data.trace) onError(data.message || "Analysis failed");
          else if (data.trace) onTrace(data);
          else onProgress(data);
        } catch { /* skip malformed SSE */ }
      }
    }
  } catch (err) {
    onError(`Stream error: ${err.message}`);
  }
}

export function buildLLMOverride(config) {
  if (!config.provider || !config.apiKey) return null;
  const override = { provider: config.provider, api_key: config.apiKey };
  if (config.model) override.model = config.model;
  if (config.baseUrl) override.base_url = config.baseUrl;
  if (config.isReasoningModel) override.is_reasoning_model = true;
  return override;
}
```

- [ ] **Step 2: Commit**

```bash
git add frontend/src/lib/api.js
git commit -m "feat(frontend): add SSE API client with event discrimination"
```

---

### Task 4: Setup page + wizard steps

**Files:**
- Create: `frontend/src/pages/Setup.jsx`
- Create: `frontend/src/pages/Setup.module.css`
- Create: `frontend/src/components/SetupWizard/StepUpload.jsx`
- Create: `frontend/src/components/SetupWizard/StepUpload.module.css`
- Create: `frontend/src/components/SetupWizard/StepRepo.jsx`
- Create: `frontend/src/components/SetupWizard/StepRepo.module.css`
- Create: `frontend/src/components/SetupWizard/StepLLM.jsx`
- Create: `frontend/src/components/SetupWizard/StepLLM.module.css`

- [ ] **Step 1: Create StepUpload.jsx**

Drag-and-drop zone with file input. On valid JSON file:
- Parse JSON, validate it has `results` array
- Show filename + finding count
- "Remove" button to clear
- If >200 findings, show warning

Props: `{ semgrepJson, onJsonLoaded, onClear }`

- [ ] **Step 2: Create StepRepo.jsx**

Repo URL input (type="url", placeholder, validates starts with `https://`).
"Private repo?" toggle button reveals git token password input.

Props: `{ repoUrl, onRepoChange, gitToken, onGitTokenChange }`

- [ ] **Step 3: Create StepLLM.jsx**

Provider radio cards (`role="radiogroup"`). On selection, show fields:
- API key (password input)
- Model (text input with datalist suggestions per provider)
- Base URL (only for fpt_cloud/openai)
- Reasoning model checkbox

Model suggestions map:
```js
const MODEL_SUGGESTIONS = {
  fpt_cloud: ["GLM-4.5"],
  openai: ["gpt-4.1", "gpt-4.1-mini", "gpt-5.4", "gpt-5.4-mini"],
  anthropic: ["claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5"],
  openrouter: ["anthropic/claude-sonnet-4-6", "openai/gpt-5.4", "openai/gpt-4.1", "google/gemini-2.5-pro"],
};
```

Props: reads/writes `llmConfig` signal directly.

- [ ] **Step 4: Create Setup.jsx page**

Three-step wizard container:
- Stepper bar at top (Step 1 / 2 / 3 with active indicator)
- Server API key banner (shown when `serverApiKey` is empty or `serverKeyError` is true)
- Renders current step component
- Back/Next/Analyze buttons in footer
- "Next" disabled until current step is valid
- "Analyze" on step 3 calls `analyzeStream()` → stores result → `route('/analyzing')`
- Theme toggle button in top-right corner

Focus management: on step change, focus first input of new step via `useRef` + `useEffect`.

- [ ] **Step 5: Create CSS modules for each component**

Dense dark style matching spec: `--panel` backgrounds, `--border` edges, `--accent` for active states. 8px grid spacing. Provider cards as `display: grid` buttons with radio semantics.

- [ ] **Step 6: Verify wizard flow in browser**

```bash
cd frontend && npm run dev
```

Navigate through all 3 steps. Verify:
- File upload accepts/rejects JSON
- Repo URL validates HTTPS
- Provider card selection shows/hides fields
- Back/Next navigation works
- Theme toggle works

- [ ] **Step 7: Commit**

```bash
git add frontend/src/pages/Setup.jsx frontend/src/pages/Setup.module.css frontend/src/components/SetupWizard/
git commit -m "feat(frontend): add setup wizard with upload, repo, and LLM steps"
```

---

### Task 5: Analyzing page + ProgressTrace

**Files:**
- Create: `frontend/src/pages/Analyzing.jsx`
- Create: `frontend/src/pages/Analyzing.module.css`
- Create: `frontend/src/components/ProgressTrace.jsx`
- Create: `frontend/src/components/ProgressTrace.module.css`

- [ ] **Step 1: Create ProgressTrace.jsx**

Renders a list of pipeline step rows. Each row:
- Status icon: spinner (in_progress), checkmark (completed), X (error), dash (skipped)
- Label from `STEP_LABELS` map
- Duration formatted (ms < 1000 → "Xms", else "X.Ys")
- Detail text (file name for per-file steps)

```js
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
```

Props: `{ events }` — array of trace event objects.

- [ ] **Step 2: Create Analyzing.jsx page**

- Guard: if no `semgrepJson` in memory, redirect to `#/`
- On mount: call `analyzeStream()` with settings from stores
- Progress bar at top, estimated from trace event count
- Current step label shown prominently
- ProgressTrace component below showing all events
- Error state: bar turns red, error message inline, "Try Again" button → redirect to `#/`
- 401 handling: set `serverKeyError`, redirect to `#/`
- On result: store in `rawResult` signal, `route('/results')`

Progress estimation logic (port from old app.js):
```js
const SETUP_STEPS = 7;
function estimateTotal(fileGroupCount) {
  return SETUP_STEPS + Math.max(1, fileGroupCount) * 3;
}
```

- [ ] **Step 3: Style with CSS module**

Centered card on `--bg` background. Progress bar with `--accent` fill. Trace rows with status-colored icons. Error message in `--danger`.

- [ ] **Step 4: Test with dev server**

Cannot test SSE without backend, but verify:
- Page renders without crash
- Redirect guard works (navigate to `#/analyzing` directly → redirected to `#/`)

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/Analyzing.jsx frontend/src/pages/Analyzing.module.css frontend/src/components/ProgressTrace.*
git commit -m "feat(frontend): add analyzing page with SSE progress trace"
```

---

### Task 6: Results page shell + FilterSidebar

**Files:**
- Create: `frontend/src/pages/Results.jsx`
- Create: `frontend/src/pages/Results.module.css`
- Create: `frontend/src/components/FilterSidebar.jsx`
- Create: `frontend/src/components/FilterSidebar.module.css`

- [ ] **Step 1: Create FilterSidebar.jsx**

Collapsible facet groups reading from `allFindings` computed signal:

- **Verdict**: checkboxes for TP/FP/Uncertain with colored indicators + counts from `counts` signal
- **File**: list of unique file paths with counts, each clickable to toggle filter
- **Severity**: ERROR/WARNING/INFO checkboxes
- **Confidence**: range input (0–100) with `role="slider"` + ARIA attributes
- "Clear all" link resets `filters` signal to defaults

Each change updates `filters` signal. Use `<aside>` landmark.

**URL sync:** On filter change, update the URL hash query params (e.g., `#/results?verdict=tp,fp&file=sw.py&minConf=50`). On Results page mount, parse hash query params and initialize `filters` signal from them. Use `window.location.hash` read/write — no extra router API needed. Browser back button restores previous filter state.

- [ ] **Step 2: Create Results.jsx page shell**

- Guard: if `rawResult` is null, redirect to `#/`
- Header bar: repo name (from `repoUrl`), commit SHA, framework badge (from `rawResult.value.sbom_profile`), summary counts, export dropdown, trace toggle, "New Analysis" button
- Three-panel layout: `<aside>` FilterSidebar | `<main>` with FindingsList + DetailPanel
- Export dropdown with click-outside dismiss (Escape key too)
- Trace toggle: collapsible section with ProgressTrace using `traceEvents` signal
- "New Analysis": calls `resetAnalysis()`, `route('/')`

CSS: `display: grid; grid-template-columns: 200px 300px 1fr;` with `height: 100dvh` minus header. Each panel `overflow-y: auto`. Mobile breakpoint at 768px collapses to single column.

- [ ] **Step 3: Style both components**

FilterSidebar: `--panel` background, facet groups with `--border` separators, checkbox custom styling with verdict colors. Results: grid layout, header bar with `--surface` background.

- [ ] **Step 4: Verify layout renders**

With mock data or dev tools, confirm three-panel layout appears correctly. Filter sidebar shows facets. Mobile: verify single-column at narrow width.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/Results.* frontend/src/components/FilterSidebar.*
git commit -m "feat(frontend): add results page shell with filter sidebar"
```

---

### Task 7: FindingsList component

**Files:**
- Create: `frontend/src/components/FindingsList.jsx`
- Create: `frontend/src/components/FindingsList.module.css`

- [ ] **Step 1: Create FindingsList.jsx**

Reads `groupedFindings` and `selectedFingerprint` signals.

- File groups: collapsible headers with arrow + path + count, `aria-expanded`
- Finding rows: `<button>` with colored dot (verdict), rule name (truncated), file:line, confidence % (`tabular-nums`)
- Selected row: accent left border
- Click handler: sets `selectedFingerprint` signal to `f.fingerprint`, resets `activeTab` to "analysis"
- Keyboard: `onKeyDown` on the list container — Up/Down arrows move selection through `filteredFindings` (find current index by fingerprint, move ±1, set new fingerprint)
- Empty state: "No findings match filters"

Row HTML structure:
```jsx
<button class={`${styles.row} ${isSelected ? styles.selected : ""}`}
        onClick={() => { selectedFingerprint.value = f.fingerprint; activeTab.value = "analysis"; }}>
  <span class={styles.dot} style={{ background: classColor(f.classification) }} />
  <span class={styles.rule}>{f.rule}</span>
  <span class={styles.meta}>{f.path}:{f.line}</span>
  <span class={styles.confidence}>{fmtConfidence(f.confidence)}</span>
</button>
```

Where `isSelected = selectedFingerprint.value === f.fingerprint`.

- [ ] **Step 2: Style with CSS module**

Compact rows, `--panel` hover, `--accent` left border on selected. File group headers with arrow rotation on expand. Text overflow ellipsis on rule names and file paths. Min-height 44px on rows for touch targets.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/components/FindingsList.*
git commit -m "feat(frontend): add file-grouped findings list with keyboard nav"
```

---

### Task 8: DetailPanel + CodeBlock

**Files:**
- Create: `frontend/src/components/DetailPanel.jsx`
- Create: `frontend/src/components/DetailPanel.module.css`
- Create: `frontend/src/components/CodeBlock.jsx`
- Create: `frontend/src/components/CodeBlock.module.css`

- [ ] **Step 1: Create CodeBlock.jsx**

Props: `{ code, highlightLine, language }`

- Parse line numbers from code string (detect `NN |` prefix format)
- Window to ±10 lines around `highlightLine`
- Syntax highlight using highlight.js core with selective language imports:

```js
import hljs from "highlight.js/lib/core";
import python from "highlight.js/languages/python";
import javascript from "highlight.js/languages/javascript";
import typescript from "highlight.js/languages/typescript";
import go from "highlight.js/languages/go";
import java from "highlight.js/languages/java";
import dockerfile from "highlight.js/languages/dockerfile";
import xml from "highlight.js/languages/xml";
import css from "highlight.js/languages/css";
import bash from "highlight.js/languages/bash";

hljs.registerLanguage("python", python);
// ... register all
```

- Render: line number column + code column. Highlighted line gets `--code-hl` background.
- For >500 lines: render unhighlighted first, defer highlighting with `requestIdleCallback`.

- [ ] **Step 2: Create DetailPanel.jsx**

Reads `selectedFinding` and `activeTab` signals.

- Header: verdict badge (`classColor` background + white text + confidence), rule name, file:line, CWE from metadata
- Tab bar: `role="tablist"`, 5 tabs (Analysis, Code, Dataflow, Enrichment, Remediation), Left/Right arrow key navigation, `aria-selected`
- Tab panels: `role="tabpanel"`, renders based on `activeTab` signal

**Analysis tab:**
- Reasoning paragraph
- Metadata grid: source badge, enclosing function, decision source, applied memory IDs

**Code tab:**
- `<CodeBlock code={f.lines} highlightLine={f.line} language={detectLang(f.path)} />`
- `detectLang`: map file extension to highlight.js language name

**Dataflow tab, Enrichment tab, Remediation tab:** placeholder "Coming in next tasks" for now.

- Empty state when no finding selected: "Select a finding to view details"

- [ ] **Step 3: Style both components**

CodeBlock: `--code-bg` background, monospace font, line numbers in `--text-tertiary`, highlighted line with `--code-hl`. DetailPanel: tabs with `--accent` bottom border, `--panel` background, header with verdict badge.

- [ ] **Step 4: Wire into Results.jsx**

Import FindingsList and DetailPanel into Results.jsx. Place FindingsList in center panel, DetailPanel in right panel.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/DetailPanel.* frontend/src/components/CodeBlock.*
git commit -m "feat(frontend): add tabbed detail panel with code highlighting"
```

---

### Task 9: DataflowView + EnrichmentView

**Files:**
- Create: `frontend/src/components/DataflowView.jsx`
- Create: `frontend/src/components/DataflowView.module.css`
- Create: `frontend/src/components/EnrichmentView.jsx`
- Create: `frontend/src/components/EnrichmentView.module.css`

- [ ] **Step 1: Create DataflowView.jsx**

Props: `{ finding }`

Two rendering modes:

**(a) Taint flow** — when `finding.graphContext?.taint_path?.length > 0`:
- Vertical step list: SOURCE (green) → PROPAGATION (amber) → SINK (red)
- First step = SOURCE, last = SINK, middle = PROPAGATION
- Sanitizer detection: if `finding.graphContext.taint_sanitizers` contains a string found in a step, mark that step as SANITIZER (green)
- Path compression: >8 steps → show first 3, "...N more steps", last 3
- Each step: colored circle + label + location text
- Connector lines between steps

**(b) Caller flow** — when no taint but callers/callees exist:
- Three vertical nodes: CALLER (blue, first caller) → FINDING (red) → CALLS (gray, callees list)
- "+N more callers" text if multiple callers

**(c) Neither** — show dataflow analysis paragraph (from `finding.dataflowAnalysis`) or "No data flow information available"

Always show `finding.dataflowAnalysis` paragraph at top if present.

- [ ] **Step 2: Create EnrichmentView.jsx**

Props: `{ finding }`

Sub-tabs within the Enrichment tab panel (not main detail tabs):
- **Callers**: table with file, line, function columns. Expandable rows showing code context via CodeBlock. Max 20 rows + "+N more" overflow.
- **Callees**: pill/chip layout. Max 20 + overflow.
- **Imports**: pill layout.
- **Taint**: reachability verdict (green dot / amber dot / red dot + text). Taint path as ordered list. Sanitizer list.

Source badge at top: "tree-sitter" / "gkg" / "Joern CPG" + enclosing function name.

If no graphContext, show "No enrichment data available".

- [ ] **Step 3: Wire into DetailPanel.jsx**

Replace Dataflow tab placeholder with `<DataflowView finding={selectedFinding.value} />`.
Replace Enrichment tab placeholder with `<EnrichmentView finding={selectedFinding.value} />`.
Replace Remediation tab placeholder with inline rendering of `finding.remediationExplanation` + `<CodeBlock>` for `finding.remediationCode`.

- [ ] **Step 4: Style both components**

DataflowView: vertical timeline with colored circles and connector lines. EnrichmentView: callers table with `--surface` row hover, pill badges with `--surface` background.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/DataflowView.* frontend/src/components/EnrichmentView.*
git commit -m "feat(frontend): add dataflow visualization and enrichment views"
```

---

### Task 10: Delete old frontend files + backend wiring

**Files:**
- Delete: `frontend/js/` (entire directory)
- Delete: `frontend/css/` (entire directory)
- Delete: old `frontend/index.html`
- Modify: `src/api/app.py:45`
- Modify: `Dockerfile:28`

- [ ] **Step 1: Delete old frontend files**

```bash
rm -rf frontend/js frontend/css
```

Note: The old `frontend/index.html` was already replaced by the Vite entry `frontend/index.html` in Task 1.

- [ ] **Step 2: Update src/api/app.py static mount**

Change line 45 from:
```python
frontend_dir = os.path.join(os.path.dirname(__file__), "../../frontend")
```
to:
```python
frontend_dir = os.path.join(os.path.dirname(__file__), "../../frontend/dist")
```

- [ ] **Step 3: Update Dockerfile**

After the existing `COPY frontend/ frontend/` line, add the Vite build step. The Dockerfile already has `nodejs` and `npm` installed (for cdxgen). Add:

```dockerfile
# Build frontend
WORKDIR /app/frontend
RUN npm install && npm run build
WORKDIR /app
```

Place this after `COPY frontend/ frontend/` and before `COPY run.py .`.

- [ ] **Step 4: Build frontend locally and verify**

```bash
cd frontend && npm run build
```

Expected: `frontend/dist/` directory created with `index.html` + `assets/`.

- [ ] **Step 5: Verify backend serves built frontend**

```bash
cd /path/to/semgrep_analyzer && python run.py
```

Open `http://localhost:8000` — should serve the Preact app.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(frontend): delete old vanilla JS, wire Vite build to backend"
```

---

### Task 11: Docker build + E2E verification

**Files:**
- No new files

- [ ] **Step 1: Rebuild Docker**

```bash
docker compose down && docker volume rm semgrep_analyzer_repos_cache semgrep_analyzer_result_cache 2>/dev/null; docker compose up --build -d
```

- [ ] **Step 2: Verify frontend loads**

Open `http://localhost:8000` — should show Setup wizard.

- [ ] **Step 3: Run full analysis via UI**

1. Enter server API key (`test-key`) when banner appears
2. Upload `findings.json` for smallweb repo
3. Enter repo URL: `https://github.com/kagisearch/smallweb.git`
4. Select OpenRouter provider, enter API key, model `openai/gpt-4.1-mini`
5. Click Analyze
6. Verify progress trace shows pipeline steps
7. Verify results page renders with three-panel layout
8. Click through findings, verify detail tabs work
9. Test filter sidebar
10. Test export JSON/Markdown
11. Test theme toggle (light/dark)
12. Test "New Analysis" returns to wizard

- [ ] **Step 4: Test error cases**

1. Wrong server API key → banner should reappear
2. Navigate directly to `#/results` → should redirect to `#/`

- [ ] **Step 5: Test mobile layout**

Resize browser to < 768px width. Verify:
- Filter sidebar collapses
- Findings list full-width
- Detail panel as overlay

- [ ] **Step 6: Commit any fixes found during E2E**

```bash
git add -A
git commit -m "fix(frontend): address E2E testing issues"
```

