// frontend/js/app.js

import { getApiKey, setApiKey, getLLMSettings, setLLMSettings, analyzeStream } from "./api.js";
import { initUpload, resetUpload } from "./upload.js";
import { renderResults } from "./results.js";

// Views
const viewUpload = document.getElementById("view-upload");
const viewProgress = document.getElementById("view-progress");
const viewResults = document.getElementById("view-results");

function showView(view) {
  [viewUpload, viewProgress, viewResults].forEach((v) => v.classList.add("hidden"));
  view.classList.remove("hidden");
}

// Theme
function initTheme() {
  const toggle = document.getElementById("theme-toggle");
  const saved = localStorage.getItem("theme");
  if (saved) document.documentElement.setAttribute("data-theme", saved);

  toggle.addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme");
    const isDark = current === "dark" || (!current && window.matchMedia("(prefers-color-scheme: dark)").matches);
    const next = isDark ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("theme", next);
  });
}

// API key popover
function initApiKeyPopover() {
  const btn = document.getElementById("settings-btn");
  const popover = document.getElementById("settings-popover");
  const input = document.getElementById("api-key-input");
  const save = document.getElementById("save-api-key");

  input.value = getApiKey();

  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    popover.classList.toggle("hidden");
    if (!popover.classList.contains("hidden")) input.focus();
  });

  save.addEventListener("click", () => {
    setApiKey(input.value.trim());
    popover.classList.add("hidden");
  });

  // Escape to close
  popover.addEventListener("keydown", (e) => {
    if (e.key === "Escape") popover.classList.add("hidden");
  });

  document.addEventListener("click", (e) => {
    if (!e.target.closest("#settings-popover") && !e.target.closest("#settings-btn")) {
      popover.classList.add("hidden");
    }
  });
}

// Model suggestions per provider
const MODEL_SUGGESTIONS = {
  fpt_cloud: ["GLM-4.5"],
  openai: ["gpt-4.1", "gpt-4.1-mini", "gpt-5.4", "gpt-5.4-mini"],
  anthropic: ["claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5"],
  openrouter: ["anthropic/claude-sonnet-4-6", "anthropic/claude-opus-4-6", "openai/gpt-5.4", "openai/gpt-4.1", "google/gemini-2.5-pro"],
};

const MODEL_DEFAULTS = {
  fpt_cloud: "GLM-4.5",
  openai: "gpt-4.1",
  anthropic: "claude-sonnet-4-6",
  openrouter: "anthropic/claude-sonnet-4-6",
};

const PROVIDER_LABELS = {
  "": "Server default",
  fpt_cloud: "FPT Cloud",
  openai: "OpenAI",
  anthropic: "Anthropic",
  openrouter: "OpenRouter",
};

// Pipeline trace step labels
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

const STEP_ICONS = {
  completed: "\u2713",
  error: "\u2717",
  skipped: "\u2014",
  in_progress: "\u27F3",
};

function formatDuration(ms) {
  if (ms == null) return "...";
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str || "";
  return div.innerHTML;
}

function renderTraceEntry(event) {
  const icon = STEP_ICONS[event.status] || "?";
  const label = STEP_LABELS[event.step] || event.step;
  const duration = formatDuration(event.duration_ms);
  const detail = escapeHtml(event.detail || "");
  return `<div class="trace-entry ${event.status}" data-step="${event.step}">` +
    `<span class="trace-icon ${event.status}">${icon}</span>` +
    `<span class="trace-label">${label}</span>` +
    `<span class="trace-duration">${duration}</span>` +
    `<span class="trace-detail">${detail}</span>` +
    `</div>`;
}

// LLM provider config (on upload page)
function initLLMConfig() {
  const cards = document.querySelectorAll(".provider-card");
  const llmFields = document.getElementById("llm-fields");
  const llmApiKeyInput = document.getElementById("llm-api-key-input");
  const llmModelInput = document.getElementById("llm-model-input");
  const modelSuggestions = document.getElementById("model-suggestions");
  const llmModelHint = document.getElementById("llm-model-hint");
  const llmBaseUrlGroup = document.getElementById("llm-base-url-group");
  const llmBaseUrlInput = document.getElementById("llm-base-url-input");
  const llmReasoningCheckbox = document.getElementById("llm-reasoning-model");
  const badge = document.getElementById("llm-config-badge");

  let selectedProvider = "";

  // Load saved
  const saved = getLLMSettings();
  selectedProvider = saved.provider;
  llmApiKeyInput.value = saved.apiKey;
  llmModelInput.value = saved.model;
  llmBaseUrlInput.value = saved.baseUrl;
  llmReasoningCheckbox.checked = saved.isReasoningModel;

  function selectProvider(provider) {
    selectedProvider = provider;

    // Update card selection
    cards.forEach((c) => {
      const isSelected = c.dataset.provider === provider;
      c.classList.toggle("selected", isSelected);
      c.setAttribute("aria-checked", isSelected);
    });

    // Update badge
    badge.textContent = PROVIDER_LABELS[provider] || "Server default";
    badge.classList.toggle("active", provider !== "");

    // Show/hide fields
    if (provider) {
      llmFields.classList.remove("hidden");
      const showBaseUrl = provider === "fpt_cloud" || provider === "openai";
      llmBaseUrlGroup.classList.toggle("hidden", !showBaseUrl);

      // Model suggestions datalist
      const suggestions = MODEL_SUGGESTIONS[provider] || [];
      modelSuggestions.innerHTML = suggestions.map((m) => `<option value="${m}">`).join("");

      // Model hint
      const def = MODEL_DEFAULTS[provider];
      llmModelHint.textContent = def ? `Default: ${def}` : "";
    } else {
      llmFields.classList.add("hidden");
      llmModelHint.textContent = "";
    }

    // Auto-save on provider change
    saveLLMSettings();
  }

  function saveLLMSettings() {
    setLLMSettings({
      provider: selectedProvider,
      apiKey: llmApiKeyInput.value.trim(),
      model: llmModelInput.value.trim(),
      baseUrl: llmBaseUrlInput.value.trim(),
      isReasoningModel: llmReasoningCheckbox.checked,
    });
  }

  // Card click handlers
  cards.forEach((card) => {
    card.addEventListener("click", () => selectProvider(card.dataset.provider));
  });

  // Auto-save on field blur
  llmApiKeyInput.addEventListener("change", saveLLMSettings);
  llmModelInput.addEventListener("change", saveLLMSettings);
  llmBaseUrlInput.addEventListener("change", saveLLMSettings);
  llmReasoningCheckbox.addEventListener("change", saveLLMSettings);

  // Initialize
  selectProvider(selectedProvider);

  // If a provider was previously saved, open the details
  if (selectedProvider) {
    document.getElementById("llm-config").setAttribute("open", "");
  }
}

// Progress
function showProgress() {
  showView(viewProgress);
  document.getElementById("progress-spinner").classList.remove("hidden");
  document.getElementById("progress-error").classList.add("hidden");
  document.getElementById("progress-step").textContent = "Starting analysis...";
  document.getElementById("progress-bar").style.width = "0%";
  const traceLog = document.getElementById("progress-trace");
  traceLog.innerHTML = "";
  traceLog.classList.add("hidden");
}

function updateProgress(data) {
  const stepNames = { repo_setup: "Setting up repository...", done: "Complete" };
  document.getElementById("progress-step").textContent = stepNames[data.step] || data.step;
  document.getElementById("progress-bar").style.width = `${data.progress || 0}%`;
}

function showError(msg) {
  document.getElementById("progress-spinner").classList.add("hidden");
  const errorDiv = document.getElementById("progress-error");
  document.getElementById("progress-error-msg").textContent = msg;
  errorDiv.classList.remove("hidden");
}

// Init
let lastRepoUrl = "";
let traceCount = 0;
let collectedTrace = [];
let fileGroupCount = 0; // learned from first per-file event

// Pipeline has ~7 setup steps, then 3 terminal events per file group.
function estimateTotal() {
  const setupSteps = 7; // repo_clone, gkg_check, gkg_index, joern_check, joern_cpg, repo_map, + buffer
  if (fileGroupCount > 0) return setupSteps + fileGroupCount * 3;
  return setupSteps + 3; // minimum: at least 1 file group
}

function handleTrace(event) {
  if (event.status !== "in_progress") {
    traceCount++;
  }
  collectedTrace.push(event);

  // Learn file group count from first per-file event
  if ((event.step === "enrich" || event.step === "llm_call") && event.detail) {
    // Count unique file prefixes seen in enrich/llm events
    const files = new Set(
      collectedTrace
        .filter((e) => e.step === "enrich" || e.step === "llm_call")
        .map((e) => (e.detail || "").split(":")[0].trim())
        .filter(Boolean)
    );
    fileGroupCount = Math.max(fileGroupCount, files.size);
  }

  const traceLog = document.getElementById("progress-trace");
  traceLog.classList.remove("hidden");

  // Replace in_progress entry for same step, or append new
  if (event.status !== "in_progress") {
    const existing = traceLog.querySelector(`.trace-entry.in_progress[data-step="${event.step}"]`);
    if (existing) {
      existing.outerHTML = renderTraceEntry(event);
    } else {
      traceLog.innerHTML += renderTraceEntry(event);
    }
  } else {
    traceLog.innerHTML += renderTraceEntry(event);
  }
  traceLog.scrollTop = traceLog.scrollHeight;

  // Progress bar based on estimated total
  const total = estimateTotal();
  const pct = Math.min(95, Math.round((traceCount / total) * 100));
  document.getElementById("progress-bar").style.width = `${pct}%`;

  // Show current step + which file is being processed
  const label = STEP_LABELS[event.step] || event.step;
  const file = event.detail ? event.detail.split(":")[0].trim() : "";
  const stepText = file && (event.step === "enrich" || event.step === "llm_call" || event.step === "parse_results")
    ? `${label} — ${file}`
    : label;
  document.getElementById("progress-step").textContent = stepText;
}

initTheme();
initApiKeyPopover();
initLLMConfig();

initUpload((repoUrl, semgrepJson, gitToken) => {
  lastRepoUrl = repoUrl;
  traceCount = 0;
  collectedTrace = [];
  fileGroupCount = 0;
  showProgress();
  analyzeStream(
    repoUrl,
    semgrepJson,
    updateProgress,
    (result) => {
      const traceData = result.trace_events || collectedTrace;
      renderResults(result, lastRepoUrl, traceData);
      showView(viewResults);
    },
    showError,
    gitToken,
    handleTrace,
  );
});

// Try Again
document.getElementById("try-again-btn").addEventListener("click", () => {
  showView(viewUpload);
});

// New Analysis
document.getElementById("new-analysis-btn").addEventListener("click", () => {
  resetUpload();
  showView(viewUpload);
});
