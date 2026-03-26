# Frontend Redesign — Vite + Preact

## Goal

Replace the vanilla JS frontend with a Vite + Preact SPA. Three-panel results layout, step wizard for setup, dense dark-first design, tabbed detail panel. Clean component architecture, no dead code, no heavy graph libraries.

## Tech Stack

- **Vite** — dev server, HMR, production build
- **Preact 10** + **preact-router** (hash-based routing) — UI components + client-side routing
- **Preact Signals** — lightweight reactive state management
- **highlight.js** (core + selective languages) — syntax highlighting for code blocks. Import `highlight.js/lib/core` and register only: python, javascript, typescript, go, java, dockerfile, html, css, bash. Keeps bundle under 50KB vs ~1MB for full library.
- **CSS Modules** — scoped component styles + global theme vars

No component library, no Cytoscape, no dagre. Hand-rolled components matching the dense/dark aesthetic.

## Project Structure

```
frontend/
  index.html                  # Vite entry (minimal shell, mounts #app)
  vite.config.js
  package.json
  src/
    main.jsx                  # render <App /> into #app
    app.jsx                   # Hash router: #/ → Setup, #/analyzing → Analyzing, #/results → Results
    stores/
      analysis.js             # Preact signals: findings, filters, selectedIndex, result
      settings.js             # Preact signals: serverApiKey, llmConfig (localStorage-backed)
    pages/
      Setup.jsx               # Step wizard container
      Analyzing.jsx           # Pipeline progress + trace
      Results.jsx             # Three-panel layout shell
    components/
      FilterSidebar.jsx       # Verdict/file/severity/confidence facets
      FindingsList.jsx        # Compact rows grouped by file
      DetailPanel.jsx         # Tabbed detail (Analysis, Code, Dataflow, Enrichment, Remediation)
      CodeBlock.jsx           # highlight.js viewer with line numbers + flagged line highlight
      DataflowView.jsx        # Taint flow steps or caller flow visualization
      EnrichmentView.jsx      # Callers table, callees pills, imports, taint verdict (renders inside Enrichment tab)
      ProgressTrace.jsx       # Pipeline step rows with status icons
      SetupWizard/
        StepUpload.jsx        # Drag-and-drop JSON upload
        StepRepo.jsx          # Repo URL + git token
        StepLLM.jsx           # Provider cards + API key + model
    lib/
      api.js                  # analyzeStream() SSE handler
      utils.js                # classify, classColor, classLabel, fmtConfidence, escapeHtml, etc.
    styles/
      theme.css               # CSS custom properties (dark + light themes)
      global.css              # Reset, typography, base styles
```

## SSE Event Protocol

The backend sends `text/event-stream` lines in format `data: <json>\n\n`. Three event types, discriminated by field presence:

1. **Trace event** — has `trace: true`. Fields: `step` (string), `status` ("in_progress"|"completed"|"error"|"skipped"), `detail` (string|null), `duration_ms` (number|null). Forwarded to trace UI.
2. **Result event** — has `result` key (object). Fields: `result.annotated_json`, `result.markdown_summary`, `result.warnings`, `result.sbom_profile`. Signals analysis complete.
3. **Error event** — has `status: "error"` and NO `trace` key. Fields: `message` (string). Signals fatal failure.

Discrimination logic in `lib/api.js`:
```js
if (data.result)                          → onResult(data.result)
else if (data.status === "error" && !data.trace) → onError(data.message)
else if (data.trace)                      → onTrace(data)
else                                      → onProgress(data)  // legacy progress events
```

## Finding Data Model

The `analysis` store parses `annotated_json.results[]` into finding objects:

```js
{
  path: string,            // r.path
  line: number,            // r.start.line
  rule: string,            // r.check_id
  message: string,         // r.extra.message
  severity: string,        // r.extra.severity
  fingerprint: string,     // r.extra.fingerprint
  classification: string,  // derived: "true_positive"|"false_positive"|"uncertain"
  confidence: number,      // x_fp_analysis.confidence
  reasoning: string,       // x_fp_analysis.reasoning
  dataflowAnalysis: string,// x_fp_analysis.dataflow_analysis
  remediationCode: string|null,
  remediationExplanation: string|null,
  verdict: string,         // x_fp_analysis.verdict (raw: "true_positive"|"false_positive"|"uncertain")
  status: string,          // x_fp_analysis.status
  decisionSource: string,  // x_fp_analysis.decision_source ("llm"|"human_override"|"none")
  appliedMemoryIds: [string], // x_fp_analysis.applied_memory_ids
  overrideId: string|null, // x_fp_analysis.override_id
  lines: string,           // r.extra.lines (code snippet)
  graphContext: {           // x_fp_analysis.graph_context (nullable)
    enclosing_function: string|null,
    callers: [{file, line, function, context}],
    callees: [string],
    imports: [string],
    source: string,         // "joern"|"gkg"|"tree_sitter"
    taint_reachable: boolean|null,
    taint_sanitized: boolean|null,
    taint_path: [string],
    taint_sanitizers: [string],
    taint_flow: object|null,   // from enricher taint tracing (may be absent in older results)
  }
}
```

Classification logic: if `confidence < 0.8` → "uncertain", else use `verdict` field.

**Note:** All backend snake_case keys (`x_fp_analysis`, `dataflow_analysis`, etc.) are converted to camelCase during parsing in `parseFindings()`. The `taint_path` strings are plain step descriptions — SOURCE/PROPAGATION/SINK labels are inferred by position (first=source, last=sink, middle=propagation) and sanitizer name matching.

**localStorage persistence:** Only settings (server API key, LLM config, repo URL) are persisted. The uploaded file and analysis results are NOT persisted — they live only in memory signals. Navigating to `#/results` without data redirects to `#/`.

## Routes

**Hash-based routing** (`#/`, `#/analyzing`, `#/results`) to avoid SPA fallback issues with FastAPI static file serving.

### `/` — Setup Wizard

Three-step flow with a stepper bar:

**Step 1 — Upload File**
- Drag-and-drop zone, validates JSON, shows filename + finding count
- "Next" enabled only when valid file loaded

**Step 2 — Repository**
- Repo URL input (HTTPS required)
- "Private repo?" toggle reveals git token field
- Back / Next buttons

**Step 3 — LLM Provider**
- Provider radio cards: Server default, FPT Cloud, OpenAI, Anthropic, OpenRouter
- Selecting a provider reveals: API key, model (with datalist suggestions), base URL (for fpt_cloud/openai only), reasoning model checkbox (for o1/o3/R1 models)
- "Analyze" button submits and navigates to `#/analyzing`

**Server API key handling:**
- On first visit (no key in localStorage), a top banner prompts: "Enter your server access token"
- Once saved, banner hidden permanently
- On 401 response, banner reappears with error styling
- Server key is never mixed with LLM config UI

**State:** `settings` store persists settings only (server API key, LLM provider/key/model/baseUrl/isReasoningModel, last repo URL) to localStorage. Uploaded file content is NOT persisted.

**Not exposed:** The optional `commit_sha` API field is not surfaced in the UI (backend auto-detects from cloned repo).

### `/analyzing` — Pipeline Progress

- Centered full-screen card
- Progress bar at top, percentage estimated from pipeline step count
- Current step shown prominently: "Enriching findings — sw.py"
- Pipeline trace below: rows with icon (spinner/check/error/skip) + label + duration + detail
- Steps appear in real-time via SSE trace events
- Error: progress bar turns red, error message inline below failing step, "Try Again" button
- On result SSE event: stores result in `analysis` store, navigates to `/results`

### `/results` — Three-Panel Layout

**Header bar** (full width, above panels):
- Repo name + commit SHA (short) + framework badge (from SBOM profile)
- Summary: "5 true · 11 false · 0 uncertain"
- Actions: Export dropdown (JSON download / Markdown copy), Trace toggle, "New Analysis" button

**Left panel — Filter Sidebar (~200px)**
- Collapsible facet groups:
  - Verdict: checkboxes (TP/FP/Uncertain) with color indicators + counts
  - File: clickable file list with counts
  - Severity: ERROR/WARNING/INFO checkboxes
  - Confidence: range slider 0–100%
- "Clear all" link resets filters
- Filters update findings list reactively via signals
- Filter state synced to URL hash query params (`#/results?verdict=tp&file=sw.py`). Navigating to `#/results` without params shows all findings. Browser back clears filter changes. Navigating directly to `#/results` without analysis data redirects to `#/`.

**Center panel — Findings List (~300px)**
- Compact rows: colored dot + rule name + file:line + confidence %
- Grouped by file: collapsible headers with arrow + path + count
- Selected row gets accent border highlight
- Keyboard: up/down arrows move selection
- Empty state: "No findings match filters"

**Right panel — Detail Panel (remaining width)**
- Header bar (always visible): verdict badge with confidence + rule name + file:line + CWE
- 5 tabs:
  - **Analysis** — reasoning paragraph + metadata cards (enrichment source, enclosing function, decision source, applied memory IDs)
  - **Code** — syntax-highlighted code (highlight.js), flagged line marked, ±10 line window, line numbers
  - **Dataflow** — dataflow analysis paragraph + taint flow step visualization or caller flow. Two rendering modes: (a) **Taint flow** when `taint_path` exists — vertical step list with SOURCE/PROPAGATION/SINK colored markers, path compression (>8 steps: show first 3 + "N more" + last 3), sanitizer steps highlighted in green when detected in taint_sanitizers. (b) **Caller flow** when no taint but callers/callees exist — three-node vertical: caller→finding→callees.
  - **Enrichment** — callers table (expandable rows with code context), callees pills, imports pills, taint reachability verdict. Rendered by `EnrichmentView.jsx`.
  - **Remediation** — explanation paragraph + code fix block (if available)
- Empty tabs show: "No [X] data available"
- Default to Analysis tab on selection change

## Visual Design System

### Dark Theme (primary)
```
--bg:              #0d1117
--panel:           #161b22
--surface:         #1f2937
--border:          #1f2937
--text:            #e5e7eb
--text-secondary:  #9ca3af
--text-tertiary:   #6b7280
--accent:          #818cf8
--danger:          #ef4444
--success:         #22c55e
--warning:         #eab308
--code-bg:         #0a0a0a
--code-text:       #e5e7eb
--code-hl:         rgba(127, 29, 29, 0.2)
```

### Light Theme
```
--bg:              #f9fafb
--panel:           #ffffff
--surface:         #f3f4f6
--border:          #e5e7eb
--text:            #111827
--text-secondary:  #6b7280
--text-tertiary:   #9ca3af
--accent:          #6366f1
--code-bg:         #1f2937
--code-text:       #e5e7eb
--code-hl:         rgba(220, 38, 38, 0.15)
```

### Typography
- UI: `-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif`
- Code: `'SF Mono', 'Fira Code', 'Cascadia Code', monospace`
- Sizes: 14px headings, 13px base, 11px secondary, 10px uppercase labels (minimum 10px for accessibility)

### Spacing
- 8px base grid: 4 / 8 / 12 / 16 / 24px increments

### Components
- Border-radius: 4px small (badges, inputs), 8px cards/panels
- 1px borders, no shadows (flat/dense)
- Verdict badges: solid bg + white text, compact format ("FP 93%")
- Tabs: bottom-border indicator in accent color
- Transitions: 150ms hover/focus, no animations. Wrapped in `@media (prefers-reduced-motion: no-preference)`.
- Text overflow: `text-overflow: ellipsis` + `overflow: hidden` on rule names, file paths in findings list
- Numeric alignment: `font-variant-numeric: tabular-nums` on confidence percentages and counts
- Contrast floor: `--text-tertiary` (#6b7280) used only for decorative/non-essential text. All body text uses `--text` or `--text-secondary` (both pass 4.5:1 on dark/light bg)

## Migration Plan

### Deleted
- `frontend/js/app.js` — replaced by `app.jsx` + pages
- `frontend/js/results.js` (773 lines) — split into 5+ components
- `frontend/js/upload.js` — replaced by `SetupWizard/` steps
- `frontend/js/utils.js` — migrated to `lib/utils.js`
- `frontend/js/api.js` — migrated to `lib/api.js`
- `frontend/js/graph.js` — deleted (no Cytoscape)
- `frontend/css/style.css` (1549 lines) — replaced by theme.css + scoped styles
- `frontend/index.html` — replaced by Vite entry

### Dead code removed
- `formatReasoning()` pipe-delimited `SOURCE:|SANITIZATION:|SINK:|EXPLOITABILITY:` parser
- Duplicated `escapeHtml()`, `STEP_LABELS`, `renderTraceEntryHTML` across files
- Cytoscape CDN scripts from index.html

### Backend changes
- `src/api/app.py` — update static mount from `frontend/` to `frontend/dist/`
- `Dockerfile` — add `npm install && npm run build` step before Python layer

### No API changes
- Same SSE protocol, same `/analyze/stream` endpoint, same response JSON shape
- Same `X-API-Key` header auth, same `llm_override` body field

## Accessibility

### Landmarks
- Results page: `<header>` (results header bar), `<aside>` (filter sidebar), `<main>` (findings list + detail panel)
- Setup/Analyzing pages: `<main>` wrapping primary content

### ARIA
- Provider radio cards: `role="radiogroup"` on container, `role="radio"` + `aria-checked` on each card
- Detail panel tabs: `role="tablist"` on tab bar, `role="tab"` + `aria-selected` on each tab, `role="tabpanel"` on content
- Confidence range slider: `role="slider"` + `aria-valuemin="0"` + `aria-valuemax="100"` + `aria-valuenow`
- Icon-only buttons (theme toggle, export, settings gear): `aria-label` required on each
- File group headers: `aria-expanded` toggled on collapse/expand
- Export dropdown: `aria-expanded` on trigger, `aria-haspopup="true"`

### Focus Management
- Wizard step transitions: focus moves to the first input of the new step
- Finding selection change: focus stays in the findings list (detail panel updates without stealing focus)
- Export dropdown: `useClickOutside` hook to dismiss; Escape key also closes
- 401 redirect: focus moves to the server token banner input

### Contrast
- All interactive text meets 4.5:1 minimum against its background
- `--text-tertiary` restricted to decorative elements (timestamps, separators), never interactive or informational text

## Keyboard Navigation

- **Results page**: Up/Down arrows move finding selection, Left/Right arrows cycle detail tabs (WAI-ARIA tabs pattern)
- **Setup wizard**: Enter advances to next step when valid
- **Analyzing page**: Escape returns to setup

## Mobile / Responsive

**Breakpoint**: `768px`. Below this threshold, layout adapts.

### Results page (< 768px)
- Filter sidebar collapses into a slide-out drawer triggered by a filter icon button
- Findings list takes full width
- Detail panel opens as a bottom sheet / overlay on finding selection, with a close/back button
- Touch targets: minimum 44x44px on all interactive elements (finding rows, tabs, buttons)

### Height strategy
- Three-panel layout uses `height: 100dvh` minus header height. Each panel scrolls independently via `overflow-y: auto`.
- Avoids `100vh` (broken on mobile Safari with address bar).

### Overflow prevention
- Long file paths and rule names: `text-overflow: ellipsis` + `white-space: nowrap` + `overflow: hidden`
- Horizontal scroll blocked on body: `overflow-x: hidden` on root

### All viewports
- Setup wizard: single-column, works as-is, max-width constrains on wide screens
- Analyzing page: centered card, works as-is

## Loading States

- **Results page**: Three-panel skeleton (empty sidebar + empty list + "Select a finding" placeholder) renders immediately. `parseFindings()` runs synchronously on route entry — fast for typical result sizes (<500 findings). For large sets (>200), consider virtualizing the findings list (render visible rows + buffer).
- **CodeBlock**: highlight.js runs synchronously on render. For files >500 lines, defer highlighting with `requestIdleCallback` and show unhighlighted code first.
- **Trace toggle on results page**: Inline collapsible section below the header bar (same pattern as current). Toggle button shows/hides.

## Error Handling

- **No data guard**: `Results.jsx` and `Analyzing.jsx` check if `analysis` store has data. If empty (direct navigation, tab restore), redirect to `#/`.
- **Corrupt localStorage**: `settings` store wraps reads in try/catch, falls back to defaults on parse error.
- **SSE connection failure**: `lib/api.js` catches network errors and calls `onError`. The Analyzing page shows the error inline with "Try Again".
- **401 from backend**: Clears server API key from store, redirects to `#/` with banner showing "Invalid server token".

## Testing

- **Unit tests** (`lib/`): SSE event discrimination logic with real backend payloads, `classify()` edge cases, `parseFindings()` with full annotated JSON fixture
- **Component tests** (Preact Testing Library): filter toggle updates findings list, finding selection renders detail, tab switching shows correct content, keyboard navigation (up/down/left/right)
- **Store tests**: settings persistence/recovery from corrupt localStorage, analysis store redirect guard
- **E2E**: manual verification against Docker container with real analysis run on smallweb repo
- **Verify**: SSE streaming, 401 handling, empty state redirects
