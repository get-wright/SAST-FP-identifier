import { useEffect } from "preact/hooks";
import { useSignal } from "@preact/signals";
import { allFindings, counts, filters } from "../stores/analysis";
import { classColor } from "../lib/utils";
import styles from "./FilterSidebar.module.css";

function syncFiltersToUrl(f) {
  const params = new URLSearchParams();
  if (f.verdicts.length) params.set("verdict", f.verdicts.join(","));
  if (f.files.length) params.set("file", f.files.join(","));
  if (f.severities.length) params.set("severity", f.severities.join(","));
  if (f.minConfidence > 0) params.set("minConf", f.minConfidence);
  const hash = params.toString() ? `/results?${params}` : "/results";
  window.location.hash = hash;
}

function parseFiltersFromUrl() {
  const hash = window.location.hash.replace("#", "");
  const idx = hash.indexOf("?");
  if (idx < 0) return null;
  const params = new URLSearchParams(hash.slice(idx + 1));
  return {
    verdicts: params.get("verdict")?.split(",").filter(Boolean) || [],
    files: params.get("file")?.split(",").filter(Boolean) || [],
    severities: params.get("severity")?.split(",").filter(Boolean) || [],
    minConfidence: parseInt(params.get("minConf") || "0", 10),
    maxConfidence: 100,
  };
}

function toggleArrayItem(arr, item) {
  return arr.includes(item) ? arr.filter((x) => x !== item) : [...arr, item];
}

const VERDICT_ITEMS = [
  { key: "true_positive", label: "True Positive" },
  { key: "false_positive", label: "False Positive" },
  { key: "uncertain", label: "Uncertain" },
];

const SEVERITY_ITEMS = ["ERROR", "WARNING", "INFO"];

function FacetGroup({ title, open, onToggle, children }) {
  return (
    <div class={styles.facetGroup}>
      <button class={styles.facetHeader} onClick={onToggle} aria-expanded={open}>
        <span class={styles.facetArrow}>{open ? "▾" : "▸"}</span>
        <span class={styles.facetTitle}>{title}</span>
      </button>
      {open && <div class={styles.facetBody}>{children}</div>}
    </div>
  );
}

export function FilterSidebar() {
  const verdictOpen = useSignal(true);
  const fileOpen = useSignal(true);
  const severityOpen = useSignal(true);
  const confidenceOpen = useSignal(true);

  // Initialize from URL on mount
  useEffect(() => {
    const parsed = parseFiltersFromUrl();
    if (parsed) {
      filters.value = parsed;
    }
  }, []);

  function updateFilters(next) {
    filters.value = next;
    syncFiltersToUrl(next);
  }

  function clearAll() {
    updateFilters({ verdicts: [], files: [], severities: [], minConfidence: 0, maxConfidence: 100 });
  }

  function toggleVerdict(key) {
    updateFilters({ ...filters.value, verdicts: toggleArrayItem(filters.value.verdicts, key) });
  }

  function toggleFile(path) {
    updateFilters({ ...filters.value, files: toggleArrayItem(filters.value.files, path) });
  }

  function toggleSeverity(sev) {
    updateFilters({ ...filters.value, severities: toggleArrayItem(filters.value.severities, sev) });
  }

  function setMinConfidence(val) {
    updateFilters({ ...filters.value, minConfidence: parseInt(val, 10) });
  }

  // Compute unique files with counts
  const fileCounts = {};
  for (const f of allFindings.value) {
    fileCounts[f.path] = (fileCounts[f.path] || 0) + 1;
  }
  const uniqueFiles = Object.keys(fileCounts).sort();

  // Severity counts
  const sevCounts = { ERROR: 0, WARNING: 0, INFO: 0 };
  for (const f of allFindings.value) {
    if (sevCounts[f.severity] !== undefined) sevCounts[f.severity]++;
  }

  const f = filters.value;
  const hasFilters =
    f.verdicts.length > 0 || f.files.length > 0 || f.severities.length > 0 || f.minConfidence > 0;

  return (
    <aside class={styles.sidebar} aria-label="Filter findings">
      <div class={styles.topRow}>
        <span class={styles.sidebarTitle}>Filters</span>
        {hasFilters && (
          <button class={styles.clearAll} onClick={clearAll}>
            Clear all
          </button>
        )}
      </div>

      {/* Verdict facet */}
      <FacetGroup
        title="Verdict"
        open={verdictOpen.value}
        onToggle={() => (verdictOpen.value = !verdictOpen.value)}
      >
        {VERDICT_ITEMS.map(({ key, label }) => {
          const checked = f.verdicts.includes(key);
          const count = counts.value[key] || 0;
          return (
            <label key={key} class={styles.checkRow}>
              <input
                type="checkbox"
                class={styles.checkbox}
                checked={checked}
                onChange={() => toggleVerdict(key)}
              />
              <span class={styles.dot} style={{ background: classColor(key) }} />
              <span class={styles.checkLabel}>{label}</span>
              <span class={styles.count}>{count}</span>
            </label>
          );
        })}
      </FacetGroup>

      {/* File facet */}
      {uniqueFiles.length > 0 && (
        <FacetGroup
          title="File"
          open={fileOpen.value}
          onToggle={() => (fileOpen.value = !fileOpen.value)}
        >
          <div class={styles.fileList}>
            {uniqueFiles.map((path) => {
              const selected = f.files.includes(path);
              const fileName = path.split("/").pop();
              return (
                <button
                  key={path}
                  class={`${styles.fileItem} ${selected ? styles.fileItemSelected : ""}`}
                  onClick={() => toggleFile(path)}
                  title={path}
                >
                  <span class={styles.fileName}>{fileName}</span>
                  <span class={styles.count}>{fileCounts[path]}</span>
                </button>
              );
            })}
          </div>
        </FacetGroup>
      )}

      {/* Severity facet */}
      <FacetGroup
        title="Severity"
        open={severityOpen.value}
        onToggle={() => (severityOpen.value = !severityOpen.value)}
      >
        {SEVERITY_ITEMS.map((sev) => {
          const checked = f.severities.includes(sev);
          return (
            <label key={sev} class={styles.checkRow}>
              <input
                type="checkbox"
                class={styles.checkbox}
                checked={checked}
                onChange={() => toggleSeverity(sev)}
              />
              <span class={styles.checkLabel}>{sev}</span>
              <span class={styles.count}>{sevCounts[sev] || 0}</span>
            </label>
          );
        })}
      </FacetGroup>

      {/* Confidence facet */}
      <FacetGroup
        title="Confidence"
        open={confidenceOpen.value}
        onToggle={() => (confidenceOpen.value = !confidenceOpen.value)}
      >
        <div class={styles.sliderRow}>
          <input
            type="range"
            min="0"
            max="100"
            value={f.minConfidence}
            role="slider"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={f.minConfidence}
            aria-label="Minimum confidence"
            class={styles.slider}
            onInput={(e) => setMinConfidence(e.target.value)}
          />
          <span class={styles.sliderValue}>{f.minConfidence}%</span>
        </div>
        <span class={styles.sliderHint}>Min confidence threshold</span>
      </FacetGroup>
    </aside>
  );
}
