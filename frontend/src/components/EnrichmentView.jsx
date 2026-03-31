import { useState } from "preact/hooks";
import styles from "./EnrichmentView.module.css";

const MAX_ROWS = 20;
const MAX_PILLS = 20;

const SOURCE_LABELS = {
  joern: "Joern CPG",
  gkg: "gkg",
  tree_sitter: "tree-sitter",
};

function sourceBadgeText(src) {
  return SOURCE_LABELS[src] || src || "unknown";
}

function CallerRow({ caller }) {
  const [open, setOpen] = useState(false);
  const hasContext = Boolean(caller.context);
  return (
    <>
      <tr
        class={`${styles.row} ${hasContext ? styles.rowClickable : ""}`}
        onClick={hasContext ? () => setOpen((v) => !v) : undefined}
        aria-expanded={hasContext ? open : undefined}
      >
        <td class={styles.td}>{caller.file || "—"}</td>
        <td class={`${styles.td} ${styles.tdNum}`}>{caller.line ?? "—"}</td>
        <td class={`${styles.td} ${styles.mono}`}>{caller.function || "—"}</td>
      </tr>
      {open && hasContext && (
        <tr>
          <td colspan={3} class={styles.contextCell}>
            <pre class={styles.contextPre}>{caller.context}</pre>
          </td>
        </tr>
      )}
    </>
  );
}

function CallersSection({ callers }) {
  if (!callers || callers.length === 0) return null;
  const shown = callers.slice(0, MAX_ROWS);
  const overflow = callers.length - shown.length;
  return (
    <section class={styles.section}>
      <h3 class={styles.sectionTitle}>Callers</h3>
      <div class={styles.tableWrap}>
        <table class={styles.table}>
          <thead>
            <tr>
              <th class={styles.th}>File</th>
              <th class={`${styles.th} ${styles.thNum}`}>Line</th>
              <th class={styles.th}>Function</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((c, i) => (
              <CallerRow key={i} caller={c} />
            ))}
          </tbody>
        </table>
      </div>
      {overflow > 0 && (
        <p class={styles.overflow}>+{overflow} more callers</p>
      )}
    </section>
  );
}

function PillsSection({ title, items }) {
  if (!items || items.length === 0) return null;
  const shown = items.slice(0, MAX_PILLS);
  const overflow = items.length - shown.length;
  return (
    <section class={styles.section}>
      <h3 class={styles.sectionTitle}>{title}</h3>
      <div class={styles.pills}>
        {shown.map((item, i) => (
          <span key={i} class={styles.pill}>{item}</span>
        ))}
        {overflow > 0 && (
          <span class={styles.overflowPill}>+{overflow} more</span>
        )}
      </div>
    </section>
  );
}

function TaintSection({ gc }) {
  const { taint_reachable, taint_sanitized, taint_path, taint_sanitizers } = gc;
  if (taint_reachable === null && taint_reachable === undefined) return null;
  if (taint_reachable === null) return null;

  let dot;
  let label;
  if (taint_sanitized) {
    dot = styles.dotBlue;
    label = "Sanitized";
  } else if (taint_reachable) {
    dot = styles.dotGreen;
    label = "Reachable";
  } else {
    dot = styles.dotRed;
    label = "Not reachable";
  }

  return (
    <section class={styles.section}>
      <h3 class={styles.sectionTitle}>Taint</h3>
      <div class={styles.taintReach}>
        <span class={`${styles.reachDot} ${dot}`} />
        <span class={styles.reachLabel}>{label}</span>
      </div>
      {taint_path && taint_path.length > 0 && (
        <div class={styles.taintBlock}>
          <p class={styles.taintBlockLabel}>Taint path</p>
          <ol class={styles.taintList}>
            {taint_path.map((step, i) => (
              <li key={i} class={styles.taintItem}>{step}</li>
            ))}
          </ol>
        </div>
      )}
      {taint_sanitizers && taint_sanitizers.length > 0 && (
        <div class={styles.taintBlock}>
          <p class={styles.taintBlockLabel}>Sanitizers</p>
          <ul class={styles.taintList}>
            {taint_sanitizers.map((s, i) => (
              <li key={i} class={styles.taintItem}>{s}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

export function EnrichmentView({ finding }) {
  const gc = finding.graphContext;

  if (!gc) {
    return <p class={styles.empty}>No enrichment data found for this finding.</p>;
  }

  const hasAny = gc.enclosing_function || gc.callers?.length || gc.callees?.length || gc.imports?.length || gc.taint_reachable != null;
  if (!hasAny) {
    return <p class={styles.empty}>No enrichment data found for this finding. This is typically a configuration or static analysis issue without traceable code structure.</p>;
  }

  const sourceText = sourceBadgeText(gc.source);
  const enclosing = gc.enclosing_function;

  return (
    <div class={styles.root}>
      <div class={styles.topBar}>
        <span class={styles.sourceBadge}>{sourceText}</span>
        {enclosing && (
          <span class={styles.enclosing}>{enclosing}</span>
        )}
      </div>
      <CallersSection callers={gc.callers} />
      <PillsSection title="Callees" items={gc.callees} />
      <PillsSection title="Imports" items={gc.imports} />
      <TaintSection gc={gc} />
    </div>
  );
}
