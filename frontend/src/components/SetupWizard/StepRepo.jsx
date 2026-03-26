import { useEffect, useRef, useState } from "preact/hooks";
import { lastRepoUrl } from "../../stores/settings";
import styles from "./StepRepo.module.css";

export function StepRepo({ repoUrl, gitToken, onChange, focusRef }) {
  const [showToken, setShowToken] = useState(false);
  const urlRef = focusRef || useRef(null);

  // Auto-populate from settings on mount
  useEffect(() => {
    if (!repoUrl && lastRepoUrl.value) {
      onChange({ repoUrl: lastRepoUrl.value, gitToken });
    }
  }, []);

  function handleUrlChange(e) {
    const val = e.target.value;
    lastRepoUrl.value = val;
    onChange({ repoUrl: val, gitToken });
  }

  function handleTokenChange(e) {
    onChange({ repoUrl, gitToken: e.target.value });
  }

  const urlError = repoUrl && !repoUrl.startsWith("https://")
    ? 'URL must start with "https://"'
    : "";

  return (
    <div class={styles.root}>
      <h2 class={styles.heading}>Repository</h2>
      <p class={styles.sub}>Where is the code that was scanned?</p>

      <div class={styles.field}>
        <label class={styles.label} for="repo-url">Repository URL</label>
        <input
          ref={urlRef}
          id="repo-url"
          type="url"
          class={`${styles.input} ${urlError ? styles.inputError : ""}`}
          placeholder="https://github.com/org/repo"
          value={repoUrl}
          onInput={handleUrlChange}
          aria-describedby={urlError ? "repo-url-error" : undefined}
          aria-invalid={!!urlError}
          autocomplete="url"
        />
        {urlError && (
          <span id="repo-url-error" class={styles.fieldError} role="alert">
            {urlError}
          </span>
        )}
      </div>

      <div class={styles.privateToggleRow}>
        <button
          type="button"
          class={`${styles.toggleBtn} ${showToken ? styles.toggleActive : ""}`}
          aria-pressed={showToken}
          onClick={() => setShowToken((v) => !v)}
        >
          {showToken ? "▾" : "▸"} Private repo?
        </button>
      </div>

      {showToken && (
        <div class={styles.field}>
          <label class={styles.label} for="git-token">Git Token</label>
          <input
            id="git-token"
            type="password"
            class={styles.input}
            placeholder="ghp_…"
            value={gitToken}
            onInput={handleTokenChange}
            autocomplete="current-password"
          />
          <span class={styles.fieldHint}>Used only for cloning — never stored on the server.</span>
        </div>
      )}
    </div>
  );
}
