// frontend/js/utils.js

const FP_THRESHOLD = 0.8;

/**
 * Derive three-state classification from annotated finding.
 * Matches backend FindingVerdict.classification() logic.
 * @param {object} analysis - x_fp_analysis object from annotated JSON
 * @returns {"true_positive"|"false_positive"|"uncertain"}
 */
export function classify(analysis) {
  if (!analysis || analysis.confidence < FP_THRESHOLD) return "uncertain";
  return analysis.verdict || "uncertain";
}

/** Map classification to display color. */
export function classColor(cls) {
  return { true_positive: "#dc2626", false_positive: "#16a34a", uncertain: "#ca8a04" }[cls] || "#78716c";
}

/** Map classification to human label. */
export function classLabel(cls) {
  return { true_positive: "True Positive", false_positive: "False Positive", uncertain: "Uncertain" }[cls] || "Unknown";
}

/** Format confidence as percentage string. */
export function fmtConfidence(val) {
  return `${Math.round((val || 0) * 100)}%`;
}

/**
 * Extract repo name from URL (last two path segments).
 * "https://github.com/org/repo" -> "org/repo"
 * "https://github.com/org/repo.git" -> "org/repo"
 */
export function repoName(url) {
  try {
    const path = new URL(url).pathname.replace(/\.git$/, "").replace(/\/$/, "");
    const parts = path.split("/").filter(Boolean);
    return parts.length >= 2 ? `${parts[parts.length - 2]}/${parts[parts.length - 1]}` : parts[parts.length - 1] || url;
  } catch {
    return url;
  }
}

/**
 * Extract short commit SHA from annotated JSON.
 * Reads from first result's x_fp_analysis.commit_sha.
 */
export function commitSha(annotatedJson) {
  const results = annotatedJson?.results || [];
  if (results.length === 0) return "unknown";
  const sha = results[0]?.extra?.x_fp_analysis?.commit_sha || "";
  return sha.slice(0, 7) || "unknown";
}

/**
 * Parse annotated JSON results into a flat findings array with classification.
 */
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
      remediationCode: a.remediation_code || null,
      remediationExplanation: a.remediation_explanation || null,
      status: a.status || "ok",
      lines: r.extra?.lines || "",
      graphContext: a.graph_context || null,
      taintReachable: a.graph_context?.taint_reachable ?? null,
      taintSanitized: a.graph_context?.taint_sanitized ?? null,
      taintPath: a.graph_context?.taint_path ?? [],
      taintSanitizers: a.graph_context?.taint_sanitizers ?? [],
    };
  });
}

/** Group findings by file path. Returns Map<string, finding[]>. */
export function groupByFile(findings) {
  const map = new Map();
  for (const f of findings) {
    if (!map.has(f.path)) map.set(f.path, []);
    map.get(f.path).push(f);
  }
  return map;
}
