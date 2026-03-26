import { useEffect, useRef } from "preact/hooks";
import { selectedFinding, activeTab } from "../stores/analysis";
import { classColor, classLabel, fmtConfidence } from "../lib/utils";
import { CodeBlock, detectLang } from "./CodeBlock";
import { DataflowView } from "./DataflowView";
import { EnrichmentView } from "./EnrichmentView";
import styles from "./DetailPanel.module.css";

const TABS = [
  { id: "analysis", label: "Analysis" },
  { id: "code", label: "Code" },
  { id: "dataflow", label: "Dataflow" },
  { id: "enrichment", label: "Enrichment" },
  { id: "remediation", label: "Remediation" },
];

const CWE_RE = /CWE-\d+/gi;

function extractCwe(rule, message) {
  const m = CWE_RE.exec(rule || "") || CWE_RE.exec(message || "");
  CWE_RE.lastIndex = 0;
  return m ? m[0].toUpperCase() : null;
}

function shortVerdict(cls) {
  return { true_positive: "TP", false_positive: "FP", uncertain: "?" }[cls] || "?";
}

function Header({ f }) {
  const cwe = extractCwe(f.rule, f.message);
  const color = classColor(f.classification);
  return (
    <div class={styles.header}>
      <div class={styles.headerTop}>
        <span class={styles.verdictBadge} style={{ background: color }}>
          {shortVerdict(f.classification)} {fmtConfidence(f.confidence)}
        </span>
        {cwe && <span class={styles.cweBadge}>{cwe}</span>}
        <span class={styles.ruleName} title={f.rule}>{f.rule}</span>
      </div>
      <div class={styles.headerLoc}>
        <span class={styles.loc}>{f.path}:{f.line}</span>
      </div>
    </div>
  );
}

function TabBar({ current, onChange }) {
  const tabsRef = useRef(null);

  function handleKeyDown(e) {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    e.preventDefault();
    const idx = TABS.findIndex((t) => t.id === current);
    let next;
    if (e.key === "ArrowRight") {
      next = TABS[(idx + 1) % TABS.length];
    } else {
      next = TABS[(idx - 1 + TABS.length) % TABS.length];
    }
    onChange(next.id);
    // Focus the newly active tab
    const btn = tabsRef.current?.querySelector(`[data-tab="${next.id}"]`);
    btn?.focus();
  }

  return (
    <div class={styles.tabBar} role="tablist" onKeyDown={handleKeyDown} ref={tabsRef}>
      {TABS.map((t) => (
        <button
          key={t.id}
          class={`${styles.tab} ${current === t.id ? styles.tabActive : ""}`}
          role="tab"
          aria-selected={current === t.id}
          data-tab={t.id}
          onClick={() => onChange(t.id)}
          tabIndex={current === t.id ? 0 : -1}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

function AnalysisTab({ f }) {
  const source = f.decisionSource || "none";
  const fnName = f.graphContext?.enclosing_function || null;
  const memIds = f.appliedMemoryIds || [];
  const enrichSrc = f.graphContext?.enrichment_source || null;

  return (
    <div class={styles.tabContent} role="tabpanel" aria-label="Analysis">
      <p class={styles.reasoning}>{f.reasoning || "No reasoning available."}</p>
      <div class={styles.metaGrid}>
        <div class={styles.metaCard}>
          <span class={styles.metaLabel}>Decision source</span>
          <span class={styles.metaValue}>
            <span class={styles.sourceBadge}>{source}</span>
          </span>
        </div>
        {fnName && (
          <div class={styles.metaCard}>
            <span class={styles.metaLabel}>Enclosing function</span>
            <span class={`${styles.metaValue} ${styles.mono}`}>{fnName}</span>
          </div>
        )}
        {enrichSrc && (
          <div class={styles.metaCard}>
            <span class={styles.metaLabel}>Enrichment source</span>
            <span class={styles.metaValue}>
              <span class={styles.sourceBadge}>{enrichSrc}</span>
            </span>
          </div>
        )}
        {memIds.length > 0 && (
          <div class={styles.metaCard}>
            <span class={styles.metaLabel}>Applied memories</span>
            <span class={`${styles.metaValue} ${styles.mono}`}>{memIds.join(", ")}</span>
          </div>
        )}
      </div>
    </div>
  );
}

function CodeTab({ f }) {
  return (
    <div class={styles.tabContent} role="tabpanel" aria-label="Code">
      <CodeBlock
        code={f.lines}
        highlightLine={f.line}
        language={detectLang(f.path)}
      />
    </div>
  );
}

function RemediationTab({ f }) {
  const hasExpl = Boolean(f.remediationExplanation);
  const hasCode = Boolean(f.remediationCode);

  if (!hasExpl && !hasCode) {
    return (
      <div class={styles.tabContent} role="tabpanel" aria-label="Remediation">
        <p class={styles.muted}>No remediation available.</p>
      </div>
    );
  }

  return (
    <div class={styles.tabContent} role="tabpanel" aria-label="Remediation">
      {hasExpl && <p class={styles.reasoning}>{f.remediationExplanation}</p>}
      {hasCode && (
        <CodeBlock
          code={f.remediationCode}
          language={detectLang(f.path)}
        />
      )}
    </div>
  );
}

export function DetailPanel() {
  const f = selectedFinding.value;
  const tab = activeTab.value;

  if (!f) {
    return (
      <div class={styles.empty}>
        <span class={styles.emptyText}>Select a finding to view details</span>
      </div>
    );
  }

  return (
    <div class={styles.panel}>
      <Header f={f} />
      <TabBar current={tab} onChange={(id) => (activeTab.value = id)} />
      {tab === "analysis" && <AnalysisTab f={f} />}
      {tab === "code" && <CodeTab f={f} />}
      {tab === "dataflow" && (
        <div class={styles.tabContent} role="tabpanel" aria-label="Dataflow">
          <DataflowView finding={f} />
        </div>
      )}
      {tab === "enrichment" && (
        <div class={styles.tabContent} role="tabpanel" aria-label="Enrichment">
          <EnrichmentView finding={f} />
        </div>
      )}
      {tab === "remediation" && <RemediationTab f={f} />}
    </div>
  );
}
