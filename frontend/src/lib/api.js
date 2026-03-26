// baseUrl defaults to "" (same-origin, since backend serves the frontend).
export async function analyzeStream(apiKey, repoUrl, semgrepJson, { onProgress, onResult, onError, onTrace, gitToken, llmOverride, baseUrl = "" }) {
  const body = { repo_url: repoUrl, semgrep_json: semgrepJson };
  if (gitToken) body.git_token = gitToken;
  if (llmOverride) body.llm_override = llmOverride;

  let response;
  try {
    response = await fetch(`${baseUrl}/analyze/stream`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
      body: JSON.stringify(body),
    });
  } catch (err) {
    onError(`Network error: ${err.message}`);
    return;
  }

  if (response.status === 401) {
    onError("__401__");
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
      buffer = lines.pop();
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("data: ")) continue;
        try {
          const data = JSON.parse(trimmed.slice(6));
          if (data.result) onResult(data.result);
          else if (data.status === "error" && !data.trace) onError(data.message || "Analysis failed");
          else if (data.trace) onTrace(data);
          else onProgress(data);
        } catch { /* skip malformed SSE */ }
      }
    }
  } catch (err) {
    onError(`Stream error: ${err.message}`);
  }
}

export function buildLLMOverride(config) {
  if (!config.provider || !config.apiKey) return null;
  const override = { provider: config.provider, api_key: config.apiKey };
  if (config.model) override.model = config.model;
  if (config.baseUrl) override.base_url = config.baseUrl;
  if (config.isReasoningModel) override.is_reasoning_model = true;
  return override;
}
