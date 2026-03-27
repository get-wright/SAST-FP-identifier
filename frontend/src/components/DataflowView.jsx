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

  return (
    <div>
      <div class={styles.callerFlow}>
        {callers.length > 0 && (
          <>
            <div class={`${styles.flowNode} ${styles.nodeBlue}`}>
              <span class={styles.nodeRole}>CALLER</span>
              <span class={styles.nodeText}>{callers[0].function}()</span>
              <span class={styles.nodeLocation}>{callers[0].file}:{callers[0].line}</span>
              {callers[0].context && (
                <code class={styles.nodeCode}>{callers[0].context.trim().split("\n").slice(0, 3).join("\n")}</code>
              )}
              {callers.length > 1 && (
                <span class={styles.nodeMore}>+{callers.length - 1} more callers</span>
              )}
            </div>
            <div class={styles.arrow}>&#x2193;</div>
          </>
        )}
        <div class={`${styles.flowNode} ${styles.nodeRed}`}>
          <span class={styles.nodeRole}>FINDING</span>
          <span class={styles.nodeText}>{enclosing}()</span>
          <span class={styles.nodeLocation}>{finding.path}:{finding.line}</span>
          {finding.lines && (
            <code class={styles.nodeCode}>{finding.lines.trim().split("\n").slice(0, 3).join("\n")}</code>
          )}
        </div>
        {callees.length > 0 && (
          <>
            <div class={styles.arrow}>&#x2193;</div>
            <div class={`${styles.flowNode} ${styles.nodeGray}`}>
              <span class={styles.nodeRole}>CALLEES</span>
              <span class={styles.nodeText}>{truncate(callees.map(c => c + "()").join(", "), 80)}</span>
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
          const isGrounded = step.grounded !== false;
          return (
            <div key={i} class={styles.step}>
              <div class={styles.stepLeft}>
                <div class={styles.dot} style={{ background: color }} />
                {!isLast && (
                  <div class={isGrounded ? styles.connector : styles.connectorDashed} />
                )}
              </div>
              <div class={styles.stepBody}>
                <div class={styles.stepHeader}>
                  <span class={styles.stepLabel} style={{ color }}>{step.label.toUpperCase()}</span>
                  {isGrounded && <span class={styles.groundedChip}>AST</span>}
                  {!isGrounded && <span class={styles.inferredChip}>inferred</span>}
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
  if (finding.dataflowAnalysis && finding.dataflowAnalysis !== "Not applicable") {
    return <p class={styles.analysis}>{finding.dataflowAnalysis}</p>;
  }
  return (
    <p class={styles.empty}>
      No dataflow data found for this finding. This is typically a configuration or static analysis issue without traceable data movement.
    </p>
  );
}
