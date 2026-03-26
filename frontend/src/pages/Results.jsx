import { useEffect, useRef } from "preact/hooks";
import { useSignal } from "@preact/signals";
import { route } from "preact-router";
import { rawResult, repoUrl, traceEvents, counts, resetAnalysis } from "../stores/analysis";
import { repoName, commitSha } from "../lib/utils";
import { ProgressTrace } from "../components/ProgressTrace";
import { FilterSidebar } from "../components/FilterSidebar";
import { FindingsList } from "../components/FindingsList";
import styles from "./Results.module.css";

function FrameworkBadge({ sbomProfile }) {
  if (!sbomProfile) return null;
  const { framework, dependencies, security_findings } = sbomProfile;
  if (!framework) return null;
  const depCount = Array.isArray(dependencies) ? dependencies.length : 0;
  const hasCsrfIssue = security_findings?.some((s) => s.type === "csrf") ?? false;
  return (
    <span class={styles.badge}>
      {framework}
      {depCount > 0 && ` · ${depCount} deps`}
      {hasCsrfIssue && " · No CSRF"}
    </span>
  );
}

export function Results() {
  const traceVisible = useSignal(false);
  const exportOpen = useSignal(false);
  const exportBtnRef = useRef(null);
  const exportMenuRef = useRef(null);
  const mobileFilterOpen = useSignal(false);

  useEffect(() => {
    if (!rawResult.value) {
      route("/");
    }
  }, []);

  // Close export dropdown on outside click or Escape
  useEffect(() => {
    function handleClick(e) {
      if (
        exportOpen.value &&
        !exportBtnRef.current?.contains(e.target) &&
        !exportMenuRef.current?.contains(e.target)
      ) {
        exportOpen.value = false;
      }
    }
    function handleKey(e) {
      if (e.key === "Escape") exportOpen.value = false;
    }
    document.addEventListener("mousedown", handleClick);
    document.addEventListener("keydown", handleKey);
    return () => {
      document.removeEventListener("mousedown", handleClick);
      document.removeEventListener("keydown", handleKey);
    };
  }, []);

  if (!rawResult.value) return null;

  function downloadJson() {
    const name = repoName(repoUrl.value).replace(/\//g, "-");
    const blob = new Blob([JSON.stringify(rawResult.value.annotated_json, null, 2)], {
      type: "application/json",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${name}-analysis.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    exportOpen.value = false;
  }

  function copyMarkdown() {
    if (rawResult.value?.markdown_summary) {
      navigator.clipboard.writeText(rawResult.value.markdown_summary);
    }
    exportOpen.value = false;
  }

  const name = repoName(repoUrl.value);
  const sha = commitSha(rawResult.value.annotated_json);
  const sbomProfile = rawResult.value.sbom_profile || null;
  const c = counts.value;

  return (
    <div class={styles.wrapper}>
      {/* Header bar */}
      <header class={styles.header}>
        <div class={styles.headerLeft}>
          <button
            class={`${styles.mobileFilterBtn} ${styles.iconBtn}`}
            aria-label="Toggle filters"
            aria-expanded={mobileFilterOpen.value}
            onClick={() => (mobileFilterOpen.value = !mobileFilterOpen.value)}
          >
            ⚙
          </button>
          <span class={styles.repoName}>{name}</span>
          <span class={styles.sha}>{sha}</span>
          <FrameworkBadge sbomProfile={sbomProfile} />
        </div>

        <div class={styles.headerCenter}>
          <span class={styles.countDanger}>{c.true_positive} true</span>
          <span class={styles.sep}>·</span>
          <span class={styles.countSuccess}>{c.false_positive} false</span>
          <span class={styles.sep}>·</span>
          <span class={styles.countWarning}>{c.uncertain} uncertain</span>
        </div>

        <div class={styles.headerRight}>
          <button
            class={`${styles.iconBtn} ${traceVisible.value ? styles.iconBtnActive : ""}`}
            onClick={() => (traceVisible.value = !traceVisible.value)}
            aria-pressed={traceVisible.value}
            title="Toggle trace"
          >
            ⏵ Trace
          </button>

          {/* Export dropdown */}
          <div class={styles.exportWrap}>
            <button
              ref={exportBtnRef}
              class={styles.iconBtn}
              onClick={() => (exportOpen.value = !exportOpen.value)}
              aria-haspopup="true"
              aria-expanded={exportOpen.value}
            >
              Export ▾
            </button>
            {exportOpen.value && (
              <div ref={exportMenuRef} class={styles.exportMenu} role="menu">
                <button class={styles.exportItem} role="menuitem" onClick={downloadJson}>
                  Download JSON
                </button>
                <button class={styles.exportItem} role="menuitem" onClick={copyMarkdown}>
                  Copy Markdown
                </button>
              </div>
            )}
          </div>

          <button
            class={styles.newAnalysisBtn}
            onClick={() => {
              resetAnalysis();
              route("/");
            }}
          >
            New Analysis
          </button>
        </div>
      </header>

      {/* Trace section */}
      {traceVisible.value && traceEvents.value.length > 0 && (
        <div class={styles.traceSection}>
          <ProgressTrace events={traceEvents.value} />
        </div>
      )}

      {/* Three-panel grid */}
      <div class={styles.panels}>
        <aside
          class={`${styles.filterPanel} ${mobileFilterOpen.value ? styles.filterPanelOpen : ""}`}
          aria-hidden={!mobileFilterOpen.value}
        >
          <FilterSidebar />
        </aside>
        <div class={styles.findingsPanel}>
          <FindingsList />
        </div>
        <div class={styles.detailPanel}>
          <div class={styles.placeholder}>Detail panel (Task 8)</div>
        </div>
      </div>
    </div>
  );
}
