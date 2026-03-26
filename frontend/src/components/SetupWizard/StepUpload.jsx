import { useRef, useState } from "preact/hooks";
import styles from "./StepUpload.module.css";

export function StepUpload({ semgrepJson, onFileLoaded, onFileRemoved, focusRef }) {
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState("");
  const inputRef = useRef(null);
  // forward focusRef to the drop zone button
  const dropRef = focusRef || useRef(null);

  function handleFile(file) {
    if (!file) return;
    if (!file.name.endsWith(".json")) {
      setError("File must be a .json file.");
      return;
    }
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const parsed = JSON.parse(e.target.result);
        if (!Array.isArray(parsed?.results)) {
          setError('Invalid Semgrep JSON: missing "results" array.');
          return;
        }
        setError("");
        onFileLoaded(parsed, file.name);
      } catch {
        setError("Could not parse JSON file.");
      }
    };
    reader.readAsText(file);
  }

  function handleDrop(e) {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer?.files?.[0];
    handleFile(file);
  }

  function handleInputChange(e) {
    handleFile(e.target.files?.[0]);
  }

  const count = semgrepJson?.results?.length ?? 0;

  return (
    <div class={styles.root}>
      <h2 class={styles.heading}>Upload Semgrep JSON</h2>
      <p class={styles.sub}>Paste or drop the raw output from <code>semgrep --json</code></p>

      {!semgrepJson ? (
        <div
          ref={dropRef}
          role="button"
          tabIndex={0}
          class={`${styles.dropZone} ${dragOver ? styles.dragOver : ""}`}
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(e) => e.key === "Enter" || e.key === " " ? inputRef.current?.click() : null}
          aria-label="Drop zone: click or drag a Semgrep JSON file here"
        >
          <span class={styles.dropIcon} aria-hidden="true">&#8659;</span>
          <span class={styles.dropPrimary}>Drop <code>.json</code> file here</span>
          <span class={styles.dropSecondary}>or click to browse</span>
          <input
            ref={inputRef}
            type="file"
            accept=".json,application/json"
            class={styles.hiddenInput}
            onChange={handleInputChange}
            tabIndex={-1}
            aria-hidden="true"
          />
        </div>
      ) : (
        <div class={styles.fileCard} ref={dropRef} tabIndex={-1}>
          <span class={styles.fileIcon} aria-hidden="true">&#x2714;</span>
          <div class={styles.fileMeta}>
            <span class={styles.fileName}>{semgrepJson._filename || "semgrep.json"}</span>
            <span class={styles.fileCount}>{count} finding{count !== 1 ? "s" : ""}</span>
          </div>
          <button class={styles.removeBtn} onClick={onFileRemoved} aria-label="Remove uploaded file">
            Remove
          </button>
        </div>
      )}

      {error && <p class={styles.error} role="alert">{error}</p>}

      {semgrepJson && count > 200 && (
        <p class={styles.warning} role="status">
          Warning: {count} findings — large batches may be slow to analyze.
        </p>
      )}
    </div>
  );
}
