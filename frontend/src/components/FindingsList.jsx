import { useSignal } from "@preact/signals";
import { groupedFindings, filteredFindings, selectedFingerprint, activeTab } from "../stores/analysis";
import { classColor, fmtConfidence } from "../lib/utils";
import styles from "./FindingsList.module.css";

function FileGroup({ filePath, findings, expandedSignal }) {
  const expanded = expandedSignal.value;

  function toggle() {
    expandedSignal.value = !expandedSignal.value;
  }

  const baseName = filePath.split("/").pop();

  return (
    <div class={styles.fileGroup}>
      <button
        class={styles.groupHeader}
        onClick={toggle}
        aria-expanded={expanded}
        title={filePath}
      >
        <span class={`${styles.arrow} ${expanded ? styles.arrowOpen : ""}`}>▸</span>
        <span class={styles.filePath} title={filePath}>{baseName}</span>
        <span class={styles.groupCount}>{findings.length}</span>
      </button>
      {expanded && (
        <div class={styles.groupBody}>
          {findings.map((f) => (
            <FindingRow key={f.fingerprint} finding={f} />
          ))}
        </div>
      )}
    </div>
  );
}

function FindingRow({ finding: f }) {
  const isSelected = selectedFingerprint.value === f.fingerprint;
  const shortRule = f.rule.split(".").pop();
  const shortPath = f.path.split("/").pop();

  function handleClick() {
    selectedFingerprint.value = f.fingerprint;
    activeTab.value = "analysis";
  }

  return (
    <button
      class={`${styles.findingRow} ${isSelected ? styles.findingRowSelected : ""}`}
      onClick={handleClick}
      data-fingerprint={f.fingerprint}
    >
      <span class={styles.dot} style={{ background: classColor(f.classification) }} />
      <span class={styles.ruleName} title={f.rule}>{shortRule}</span>
      <span class={styles.fileInfo}>{shortPath}:{f.line}</span>
      <span class={styles.confidence}>{fmtConfidence(f.confidence)}</span>
    </button>
  );
}

export function FindingsList() {
  const grouped = groupedFindings.value;
  const flat = filteredFindings.value;

  // One expanded signal per file group — stable across re-renders via a map
  const expandedMap = useSignal(new Map());

  function getExpanded(filePath) {
    if (!expandedMap.value.has(filePath)) {
      // Mutate the map and trigger by reassigning the signal
      const next = new Map(expandedMap.value);
      next.set(filePath, { value: true });
      expandedMap.value = next;
    }
    return expandedMap.value.get(filePath);
  }

  function handleKeyDown(e) {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    if (flat.length === 0) return;
    e.preventDefault();

    const currentIdx = flat.findIndex((f) => f.fingerprint === selectedFingerprint.value);
    let nextIdx;
    if (currentIdx < 0) {
      nextIdx = e.key === "ArrowDown" ? 0 : flat.length - 1;
    } else if (e.key === "ArrowDown") {
      nextIdx = Math.min(currentIdx + 1, flat.length - 1);
    } else {
      nextIdx = Math.max(currentIdx - 1, 0);
    }

    selectedFingerprint.value = flat[nextIdx].fingerprint;
    activeTab.value = "analysis";

    // Focus the newly selected row
    const row = e.currentTarget.querySelector(`[data-fingerprint="${flat[nextIdx].fingerprint}"]`);
    row?.focus();
  }

  if (flat.length === 0) {
    return (
      <div class={styles.empty}>No findings match filters</div>
    );
  }

  return (
    <div class={styles.list} onKeyDown={handleKeyDown} role="list">
      {[...grouped.entries()].map(([filePath, findings]) => (
        <FileGroup
          key={filePath}
          filePath={filePath}
          findings={findings}
          expandedSignal={getExpanded(filePath)}
        />
      ))}
    </div>
  );
}
