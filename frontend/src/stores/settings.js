import { signal, effect } from "@preact/signals";

function loadJSON(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

export const llmConfig = signal(loadJSON("llm_config", {
  provider: "",
  apiKey: "",
  model: "",
  baseUrl: "",
  isReasoningModel: false,
}));

export const lastRepoUrl = signal(localStorage.getItem("last_repo_url") || "");

// Auto-persist on change
effect(() => localStorage.setItem("llm_config", JSON.stringify(llmConfig.value)));
effect(() => localStorage.setItem("last_repo_url", lastRepoUrl.value));
