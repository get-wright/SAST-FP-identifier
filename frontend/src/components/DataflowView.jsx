import { useState } from "preact/hooks";
import styles from "./DataflowView.module.css";

const COMPRESS_THRESHOLD = 8;
const COMPRESS_HEAD = 3;
const COMPRESS_TAIL = 3;

function stepRole(idx, total, text, sanitizers) {
  if (sanitizers && sanitizers.some((s) => text.includes(s))) {
    return "sanitizer";
  }
  if (idx === 0) return "source";
  if (idx === total - 1) return "sink";
  return "propagation";
}

const ROLE_LABELS = {
  source: "SOURCE",
  sink: "SINK",
  propagation: "PROPAGATION",
  sanitizer: "SANITIZER",
};

function TaintFlow({ finding }) {
  const { taint_path, taint_sanitizers, taint_reachable } = finding.graphContext;
  const sanitizers = taint_sanitizers || [];
  const total = taint_path.length;

  let steps;
  let compressed = null;
  if (total > COMPRESS_THRESHOLD) {
    const head = taint_path.slice(0, COMPRESS_HEAD);
    const tail = taint_path.slice(total - COMPRESS_TAIL);
    compressed = total - COMPRESS_HEAD - COMPRESS_TAIL;
    steps = { head, tail, compressed };
  }

  function renderStep(text, idx, globalIdx) {
    const role = stepRole(globalIdx, total, text, sanitizers);
    return (
      <div key={globalIdx} class={styles.step}>
        <div class={styles.stepLeft}>
          <div class={`${styles.dot} ${styles[`dot_${role}`]}`} />
          {globalIdx < total - 1 && <div class={styles.connector} />}
        </div>
        <div class={styles.stepBody}>
          <span class={styles.stepLabel}>{ROLE_LABELS[role]}</span>
          <span class={styles.stepText}>{text}</span>
        </div>
      </div>
    );
  }

  return (
    <div>
      {finding.dataflowAnalysis && (
        <p class={styles.analysis}>{finding.dataflowAnalysis}</p>
      )}
      <div class={styles.timeline}>
        {compressed !== null ? (
          <>
            {steps.head.map((t, i) => renderStep(t, i, i))}
            <div class={styles.step}>
              <div class={styles.stepLeft}>
                <div class={styles.dotPlaceholder} />
                <div class={styles.connector} />
              </div>
              <div class={styles.stepBody}>
                <span class={styles.compressed}>...{steps.compressed} more steps</span>
              </div>
            </div>
            {steps.tail.map((t, i) =>
              renderStep(t, i, COMPRESS_HEAD + compressed + i)
            )}
          </>
        ) : (
          taint_path.map((t, i) => renderStep(t, i, i))
        )}
      </div>
      {taint_reachable !== null && (
        <div class={styles.reachability}>
          {taint_reachable ? (
            <span class={styles.reachYes}>&#x2713; Reachable</span>
          ) : (
            <span class={styles.reachNo}>&#x2715; Not reachable</span>
          )}
        </div>
      )}
    </div>
  );
}

function truncate(str, max) {
  if (!str || str.length <= max) return str;
  return str.slice(0, max) + "…";
}

function CallerFlow({ finding }) {
  const gc = finding.graphContext;
  const callers = gc?.callers || [];
  const callees = gc?.callees || [];
  const enclosing = gc?.enclosing_function || "unknown";

  const callerLabel = callers.length > 0
    ? callers[0].function + (callers.length > 1 ? ` +${callers.length - 1} more` : "")
    : null;

  const calleesLabel = callees.length > 0
    ? truncate(callees.join(", "), 60)
    : null;

  return (
    <div>
      <div class={styles.callerFlow}>
        {callerLabel && (
          <>
            <div class={`${styles.flowNode} ${styles.nodeBlue}`}>
              <span class={styles.nodeRole}>CALLER</span>
              <span class={styles.nodeText}>{callerLabel}</span>
            </div>
            <div class={styles.arrow}>&#x2193;</div>
          </>
        )}
        <div class={`${styles.flowNode} ${styles.nodeRed}`}>
          <span class={styles.nodeRole}>FINDING</span>
          <span class={styles.nodeText}>{enclosing}</span>
        </div>
        {calleesLabel && (
          <>
            <div class={styles.arrow}>&#x2193;</div>
            <div class={`${styles.flowNode} ${styles.nodeGray}`}>
              <span class={styles.nodeRole}>CALLEES</span>
              <span class={styles.nodeText}>{calleesLabel}</span>
            </div>
          </>
        )}
      </div>
      {finding.dataflowAnalysis && (
        <p class={styles.analysis}>{finding.dataflowAnalysis}</p>
      )}
    </div>
  );
}

const ROLE_COLORS = {
  source: "var(--success)",
  propagation: "var(--warning)",
  sanitizer: "#3b82f6",
  sink: "var(--danger)",
};

function LLMFlowSteps({ steps, dataflowAnalysis }) {
  return (
    <div>
      <div class={styles.timeline}>
        {steps.map((step, i) => {
          const isLast = i === steps.length - 1;
          const color = ROLE_COLORS[step.label] || "var(--text-tertiary)";
          return (
            <div key={i} class={styles.step}>
              <div class={styles.stepLeft}>
                <div class={styles.dot} style={{ background: color }} />
                {!isLast && <div class={styles.connector} />}
              </div>
              <div class={styles.stepBody}>
                <div class={styles.stepHeader}>
                  <span class={styles.stepLabel} style={{ color }}>{step.label.toUpperCase()}</span>
                  {step.location && (
                    <span class={styles.stepLocation}>{step.location}</span>
                  )}
                </div>
                {step.code && (
                  <code class={styles.stepCode}>{step.code}</code>
                )}
                {step.explanation && (
                  <span class={styles.stepExplanation}>{step.explanation}</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
      {dataflowAnalysis && (
        <p class={styles.analysis}>{dataflowAnalysis}</p>
      )}
    </div>
  );
}

export function DataflowView({ finding }) {
  const gc = finding.graphContext;
  const hasLLMSteps = finding.flowSteps?.length > 0;
  const hasTaint = gc?.taint_path?.length > 0;
  const hasCallers = (gc?.callers?.length > 0) || (gc?.callees?.length > 0);

  // Priority: LLM structured steps > enrichment taint path > caller flow > text only
  if (hasLLMSteps) {
    return <LLMFlowSteps steps={finding.flowSteps} dataflowAnalysis={finding.dataflowAnalysis} />;
  }
  if (hasTaint) {
    return <TaintFlow finding={finding} />;
  }
  if (hasCallers) {
    return <CallerFlow finding={finding} />;
  }
  if (finding.dataflowAnalysis) {
    return <p class={styles.analysis}>{finding.dataflowAnalysis}</p>;
  }
  return <p class={styles.empty}>No data flow information available.</p>;
}
