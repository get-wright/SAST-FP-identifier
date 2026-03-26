import styles from "./ProgressTrace.module.css";

export const STEP_LABELS = {
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

function formatDuration(ms) {
  if (ms == null) return null;
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function StatusIcon({ status }) {
  if (status === "in_progress") return <span class={`${styles.icon} ${styles.iconProgress}`}>⟳</span>;
  if (status === "completed") return <span class={`${styles.icon} ${styles.iconCompleted}`}>✓</span>;
  if (status === "error") return <span class={`${styles.icon} ${styles.iconError}`}>✗</span>;
  if (status === "skipped") return <span class={`${styles.icon} ${styles.iconSkipped}`}>—</span>;
  return <span class={`${styles.icon} ${styles.iconSkipped}`}>·</span>;
}

export function ProgressTrace({ events }) {
  if (!events || events.length === 0) return null;

  return (
    <ol class={styles.list} aria-label="Pipeline progress">
      {events.map((event, i) => {
        const label = STEP_LABELS[event.step] || event.step;
        const duration = formatDuration(event.duration_ms);
        return (
          <li key={i} class={styles.row}>
            <StatusIcon status={event.status} />
            <span class={styles.label}>{label}</span>
            {event.detail && <span class={styles.detail}>{event.detail}</span>}
            {duration && <span class={styles.duration}>{duration}</span>}
          </li>
        );
      })}
    </ol>
  );
}
