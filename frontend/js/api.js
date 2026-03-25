// frontend/js/api.js

/** Get API key from localStorage. */
export function getApiKey() {
  return localStorage.getItem("semgrep_api_key") || "";
}

/** Set API key in localStorage. */
export function setApiKey(key) {
  localStorage.setItem("semgrep_api_key", key);
}

/** Get LLM settings from localStorage. */
export function getLLMSettings() {
  return {
    provider: localStorage.getItem("llm_provider") || "",
    apiKey: localStorage.getItem("llm_api_key") || "",
    model: localStorage.getItem("llm_model") || "",
    baseUrl: localStorage.getItem("llm_base_url") || "",
    isReasoningModel: localStorage.getItem("llm_is_reasoning_model") === "true",
  };
}

/** Save LLM settings to localStorage. */
export function setLLMSettings({ provider, apiKey, model, baseUrl, isReasoningModel }) {
  localStorage.setItem("llm_provider", provider || "");
  localStorage.setItem("llm_api_key", apiKey || "");
  localStorage.setItem("llm_model", model || "");
  localStorage.setItem("llm_base_url", baseUrl || "");
  localStorage.setItem("llm_is_reasoning_model", isReasoningModel ? "true" : "false");
}

/**
 * Build the llm_override object for the request body, or null if not configured.
 */
function buildLLMOverride() {
  const s = getLLMSettings();
  if (!s.provider || !s.apiKey) return null;
  const override = { provider: s.provider, api_key: s.apiKey };
  if (s.model) override.model = s.model;
  if (s.baseUrl) override.base_url = s.baseUrl;
  if (s.isReasoningModel) override.is_reasoning_model = true;
  return override;
}

/**
 * Stream analysis via POST /analyze/stream.
 * Uses fetch + ReadableStream (not EventSource) since we need POST.
 *
 * @param {string} repoUrl
 * @param {object} semgrepJson - parsed Semgrep JSON
 * @param {function} onProgress - called with {step, status, progress, message?}
 * @param {function} onResult - called with {annotated_json, markdown_summary, warnings}
 * @param {function} onError - called with error message string
 * @param {string|null} gitToken - OAuth/PAT token for private repos
 */
export async function analyzeStream(repoUrl, semgrepJson, onProgress, onResult, onError, gitToken = null, onTrace = null) {
  const apiKey = getApiKey();
  if (!apiKey) {
    onError("API key not set. Click the gear icon to configure it.");
    return;
  }

  const body = { repo_url: repoUrl, semgrep_json: semgrepJson };
  if (gitToken) body.git_token = gitToken;
  const llmOverride = buildLLMOverride();
  if (llmOverride) body.llm_override = llmOverride;

  let response;
  try {
    response = await fetch("/analyze/stream", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": apiKey,
      },
      body: JSON.stringify(body),
    });
  } catch (err) {
    onError(`Network error: ${err.message}`);
    return;
  }

  if (response.status === 401) {
    onError("Invalid API key. Check your settings.");
    return;
  }

  if (!response.ok) {
    const text = await response.text();
    onError(`Server error (${response.status}): ${text}`);
    return;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n\n");
      buffer = lines.pop(); // keep incomplete chunk

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("data: ")) continue;
        try {
          const data = JSON.parse(trimmed.slice(6));
          if (data.result) {
            onResult(data.result);
          } else if (data.status === "error" && !data.trace) {
            onError(data.message || "Analysis failed");
          } else if (data.trace) {
            if (onTrace) onTrace(data);
          } else {
            onProgress(data);
          }
        } catch {
          // skip malformed SSE lines
        }
      }
    }
  } catch (err) {
    onError(`Stream error: ${err.message}`);
  }
}
