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
      flowSteps: a.flow_steps || [],
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
