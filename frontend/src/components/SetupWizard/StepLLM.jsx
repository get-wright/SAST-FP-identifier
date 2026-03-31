import { useEffect, useRef } from "preact/hooks";
import { llmConfig } from "../../stores/settings";
import styles from "./StepLLM.module.css";

const PROVIDERS = [
  { id: "server_default", label: "Server default" },
  { id: "fpt_cloud", label: "FPT Cloud" },
  { id: "openai", label: "OpenAI" },
  { id: "anthropic", label: "Anthropic" },
  { id: "openrouter", label: "OpenRouter" },
];

const MODEL_SUGGESTIONS = {
  fpt_cloud: ["GLM-4.5"],
  openai: ["gpt-4.1", "gpt-4.1-mini", "gpt-5.4", "gpt-5.4-mini"],
  anthropic: ["claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5"],
  openrouter: [
    "anthropic/claude-sonnet-4-6",
    "openai/gpt-5.4",
    "openai/gpt-4.1",
    "google/gemini-2.5-pro",
  ],
};

const SHOW_BASE_URL = new Set(["fpt_cloud", "openai"]);

export function StepLLM({ focusRef }) {
  const firstCardRef = focusRef || useRef(null);
  const cfg = llmConfig.value;

  function updateCfg(patch) {
    llmConfig.value = { ...llmConfig.value, ...patch };
  }

  function selectProvider(id) {
    updateCfg({ provider: id, model: "", baseUrl: "", apiKey: "", isReasoningModel: false });
  }

  const provider = cfg.provider || "server_default";
  const suggestions = MODEL_SUGGESTIONS[provider] || [];
  const listId = `model-suggestions-${provider}`;

  return (
    <div class={styles.root}>
      <h2 class={styles.heading}>LLM Provider</h2>
      <p class={styles.sub}>Choose which model analyzes your findings.</p>

      <div
        class={styles.providerGrid}
        role="radiogroup"
        aria-label="LLM provider"
      >
        {PROVIDERS.map((p, i) => (
          <button
            key={p.id}
            ref={i === 0 ? firstCardRef : undefined}
            type="button"
            role="radio"
            aria-checked={provider === p.id}
            class={`${styles.providerCard} ${provider === p.id ? styles.providerSelected : ""}`}
            onClick={() => selectProvider(p.id)}
          >
            {p.label}
          </button>
        ))}
      </div>

      {provider !== "server_default" && (
        <div class={styles.fields}>
          <div class={styles.field}>
            <label class={styles.label} for="llm-apikey">API Key</label>
            <input
              id="llm-apikey"
              type="password"
              class={styles.input}
              placeholder="sk-…"
              value={cfg.apiKey}
              onInput={(e) => updateCfg({ apiKey: e.target.value })}
              autocomplete="current-password"
            />
          </div>

          <div class={styles.field}>
            <label class={styles.label} for="llm-model">Model</label>
            <input
              id="llm-model"
              type="text"
              class={styles.input}
              placeholder={suggestions[0] || "model name"}
              value={cfg.model}
              list={listId}
              onInput={(e) => updateCfg({ model: e.target.value })}
              autocomplete="off"
            />
            <datalist id={listId}>
              {suggestions.map((s) => <option key={s} value={s} />)}
            </datalist>
          </div>

          {SHOW_BASE_URL.has(provider) && (
            <div class={styles.field}>
              <label class={styles.label} for="llm-baseurl">Base URL</label>
              <input
                id="llm-baseurl"
                type="url"
                class={styles.input}
                placeholder="https://api.example.com/v1"
                value={cfg.baseUrl}
                onInput={(e) => updateCfg({ baseUrl: e.target.value })}
                autocomplete="url"
              />
            </div>
          )}

          <label class={styles.checkboxRow}>
            <input
              type="checkbox"
              class={styles.checkbox}
              checked={cfg.isReasoningModel}
              onChange={(e) => updateCfg({ isReasoningModel: e.target.checked })}
            />
            <span class={styles.checkboxLabel}>Reasoning model (o1 / o3 / R1 — disables system prompt)</span>
          </label>
        </div>
      )}

      {provider === "server_default" && (
        <p class={styles.serverNote}>
          The server's configured LLM will be used. No additional credentials needed.
        </p>
      )}
    </div>
  );
}
