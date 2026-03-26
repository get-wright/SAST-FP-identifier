import { useEffect, useRef } from "preact/hooks";
import { useSignal } from "@preact/signals";
import { route } from "preact-router";
import { serverApiKey, serverKeyError, llmConfig } from "../stores/settings";
import { rawResult, repoUrl, traceEvents } from "../stores/analysis";
import { analyzeStream, buildLLMOverride } from "../lib/api";
import { ProgressTrace } from "../components/ProgressTrace";
import styles from "./Analyzing.module.css";

const SETUP_STEPS = 7;

export function Analyzing() {
  const events = useSignal([]);
  const progressPct = useSignal(0);
  const currentLabel = useSignal("Starting…");
  const errorMsg = useSignal(null);
  const fileGroupCount = useRef(0);

  function estimateTotal() {
    return SETUP_STEPS + Math.max(1, fileGroupCount.current) * 3;
  }

  function recalcProgress(collected) {
    const completed = collected.filter((e) => e.status !== "in_progress").length;
    const pct = Math.min(95, Math.round((completed / estimateTotal()) * 100));
    progressPct.value = pct;
  }

  function handleTrace(event) {
    // Replace in_progress entry for same step with completed/error/skipped, or append new
    let collected;
    if (event.status !== "in_progress") {
      const existing = events.value.findIndex(
        (e) => e.step === event.step && e.status === "in_progress" && e.detail === event.detail
      );
      if (existing >= 0) {
        collected = [...events.value];
        collected[existing] = event;
      } else {
        collected = [...events.value, event];
      }
    } else {
      collected = [...events.value, event];
    }
    events.value = collected;

    // Update file group count
    if ((event.step === "enrich" || event.step === "llm_call") && event.detail) {
      const files = new Set(
        collected
          .filter((e) => e.step === "enrich" || e.step === "llm_call")
          .map((e) => (e.detail || "").split(":")[0].trim())
          .filter(Boolean)
      );
      fileGroupCount.current = Math.max(fileGroupCount.current, files.size);
    }

    recalcProgress(collected);

    if (event.status === "in_progress") {
      const STEP_LABELS = {
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
      const label = STEP_LABELS[event.step] || event.step;
      currentLabel.value = event.detail ? `${label} — ${event.detail}` : label;
    }
  }

  function handleResult(result) {
    rawResult.value = result;
    traceEvents.value = events.value;
    sessionStorage.removeItem("semgrep_json_pending");
    progressPct.value = 100;
    route("/results");
  }

  function handleError(msg) {
    if (msg === "__401__") {
      serverKeyError.value = true;
      route("/");
      return;
    }
    errorMsg.value = msg;
    progressPct.value = 0;
  }

  useEffect(() => {
    const semgrepRaw = sessionStorage.getItem("semgrep_json_pending");
    if (!semgrepRaw) {
      route("/");
      return;
    }

    let semgrepJson;
    try {
      semgrepJson = JSON.parse(semgrepRaw);
    } catch {
      route("/");
      return;
    }

    const gitToken = sessionStorage.getItem("git_token_pending") || "";
    const llmOverride = buildLLMOverride(llmConfig.value);

    analyzeStream(
      serverApiKey.value,
      repoUrl.value,
      semgrepJson,
      {
        onProgress: () => {},
        onResult: handleResult,
        onError: handleError,
        onTrace: handleTrace,
        gitToken,
        llmOverride,
      }
    );
  }, []);

  const isError = errorMsg.value !== null;

  return (
    <div class={styles.page}>
      <div class={styles.card}>
        <h1 class={styles.title}>Analyzing</h1>

        {/* Progress bar */}
        <div
          class={styles.progressTrack}
          role="progressbar"
          aria-valuenow={progressPct.value}
          aria-valuemin={0}
          aria-valuemax={100}
        >
          <div
            class={`${styles.progressBar} ${isError ? styles.progressBarError : ""}`}
            style={{ width: `${isError ? 100 : progressPct.value}%` }}
          />
        </div>

        {/* Current step label */}
        {!isError && (
          <p class={styles.currentStep}>{currentLabel.value}</p>
        )}

        {/* Error state */}
        {isError && (
          <div class={styles.errorBox} role="alert">
            <p class={styles.errorText}>{errorMsg.value}</p>
            <button class={styles.retryBtn} onClick={() => route("/")}>
              Try Again
            </button>
          </div>
        )}

        {/* Trace events */}
        {events.value.length > 0 && (
          <div class={styles.traceWrapper}>
            <ProgressTrace events={events.value} />
          </div>
        )}
      </div>
    </div>
  );
}
