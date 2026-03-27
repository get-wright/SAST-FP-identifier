import { useEffect, useRef, useState } from "preact/hooks";
import { route } from "preact-router";
import { repoUrl as analysisRepoUrl } from "../stores/analysis";
import { StepUpload } from "../components/SetupWizard/StepUpload";
import { StepRepo } from "../components/SetupWizard/StepRepo";
import { StepLLM } from "../components/SetupWizard/StepLLM";
import styles from "./Setup.module.css";

const STEPS = ["Upload File", "Repository", "LLM Provider"];

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme");
  const isDark =
    current === "dark" ||
    (!current && window.matchMedia("(prefers-color-scheme: dark)").matches);
  const next = isDark ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem("theme", next);
}

export function Setup() {
  // Restore saved theme on mount
  useEffect(() => {
    const saved = localStorage.getItem("theme");
    if (saved) document.documentElement.setAttribute("data-theme", saved);
  }, []);

  const [step, setStep] = useState(0);

  // Step 1 state
  const [semgrepJson, setSemgrepJson] = useState(null);

  // Step 2 state
  const [repoUrl, setRepoUrl] = useState("");
  const [gitToken, setGitToken] = useState("");

  // Focus management — one ref per step
  const step0Ref = useRef(null);
  const step1Ref = useRef(null);
  const step2Ref = useRef(null);
  const stepRefs = [step0Ref, step1Ref, step2Ref];

  useEffect(() => {
    // Small delay so the DOM has rendered before we try to focus
    const id = setTimeout(() => stepRefs[step].current?.focus(), 50);
    return () => clearTimeout(id);
  }, [step]);

  function handleFileLoaded(parsed, filename) {
    setSemgrepJson({ ...parsed, _filename: filename });
  }

  function handleFileRemoved() {
    setSemgrepJson(null);
  }

  function handleRepoChange({ repoUrl: url, gitToken: tok }) {
    setRepoUrl(url);
    setGitToken(tok);
  }

  function isStepValid() {
    if (step === 0) return semgrepJson !== null;
    if (step === 1) return repoUrl.startsWith("https://");
    return true; // step 2: server default is always ok
  }

  function handleBack() {
    if (step > 0) setStep(step - 1);
  }

  function handleNext() {
    if (step < 2 && isStepValid()) setStep(step + 1);
  }

  function handleAnalyze() {
    analysisRepoUrl.value = repoUrl;
    // Store semgrepJson in sessionStorage for the Analyzing page to read
    sessionStorage.setItem("semgrep_json_pending", JSON.stringify(semgrepJson));
    sessionStorage.setItem("git_token_pending", gitToken);
    route("/analyzing");
  }

  return (
    <div class={styles.page}>
      {/* Header */}
      <header class={styles.header}>
        <span class={styles.appTitle}>Semgrep Analyzer</span>
        <button
          class={styles.themeBtn}
          onClick={toggleTheme}
          aria-label="Toggle theme"
        >
          <span aria-hidden="true" class={styles.themeIcon}>◑</span>
        </button>
      </header>

      <div class={styles.content}>
        {/* Server API key banner */}
        {/* Stepper */}
        <nav class={styles.stepper} aria-label="Wizard steps">
          {STEPS.map((label, i) => (
            <div
              key={label}
              class={`${styles.stepItem} ${i === step ? styles.stepActive : ""} ${i < step ? styles.stepDone : ""}`}
              aria-current={i === step ? "step" : undefined}
            >
              <span class={styles.stepNum}>{i + 1}</span>
              <span class={styles.stepLabel}>{label}</span>
            </div>
          ))}
        </nav>

        {/* Step content */}
        <main class={styles.card}>
          {step === 0 && (
            <StepUpload
              semgrepJson={semgrepJson}
              onFileLoaded={handleFileLoaded}
              onFileRemoved={handleFileRemoved}
              focusRef={step0Ref}
            />
          )}
          {step === 1 && (
            <StepRepo
              repoUrl={repoUrl}
              gitToken={gitToken}
              onChange={handleRepoChange}
              focusRef={step1Ref}
            />
          )}
          {step === 2 && (
            <StepLLM focusRef={step2Ref} />
          )}
        </main>

        {/* Footer navigation */}
        <footer class={styles.footer}>
          <div class={styles.footerLeft}>
            {step > 0 && (
              <button class={styles.btnSecondary} onClick={handleBack}>
                Back
              </button>
            )}
          </div>
          <div class={styles.footerRight}>
            {step < 2 && (
              <button
                class={styles.btnPrimary}
                onClick={handleNext}
                disabled={!isStepValid()}
              >
                Next
              </button>
            )}
            {step === 2 && (
              <button class={styles.btnPrimary} onClick={handleAnalyze}>
                Analyze
              </button>
            )}
          </div>
        </footer>
      </div>
    </div>
  );
}
