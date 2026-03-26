import { signal, computed } from "@preact/signals";
import { parseFindings, groupByFile } from "../lib/utils";

export const rawResult = signal(null);
export const repoUrl = signal("");
export const traceEvents = signal([]);
export const selectedFingerprint = signal(null);
export const activeTab = signal("analysis");

export const filters = signal({
  verdicts: [],
  files: [],
  severities: [],
  minConfidence: 0,
  maxConfidence: 100,
});

export const allFindings = computed(() => {
  if (!rawResult.value) return [];
  return parseFindings(rawResult.value.annotated_json);
});

export const filteredFindings = computed(() => {
  const f = filters.value;
  return allFindings.value.filter((finding) => {
    if (f.verdicts.length && !f.verdicts.includes(finding.classification)) return false;
    if (f.files.length && !f.files.includes(finding.path)) return false;
    if (f.severities.length && !f.severities.includes(finding.severity)) return false;
    const confPct = Math.round(finding.confidence * 100);
    if (confPct < f.minConfidence || confPct > f.maxConfidence) return false;
    return true;
  });
});

export const groupedFindings = computed(() => groupByFile(filteredFindings.value));

export const selectedFinding = computed(() => {
  const fp = selectedFingerprint.value;
  if (!fp) return null;
  return allFindings.value.find((f) => f.fingerprint === fp) || null;
});

export const counts = computed(() => {
  const c = { true_positive: 0, false_positive: 0, uncertain: 0 };
  for (const f of allFindings.value) c[f.classification]++;
  return c;
});

export function resetAnalysis() {
  rawResult.value = null;
  repoUrl.value = "";
  traceEvents.value = [];
  selectedFingerprint.value = null;
  activeTab.value = "analysis";
  filters.value = { verdicts: [], files: [], severities: [], minConfidence: 0, maxConfidence: 100 };
}
