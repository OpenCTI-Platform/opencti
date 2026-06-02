// Shared XTM One agent API helpers — used by AIInsights, AISummaryContainers,
// and ResponseDialog to avoid duplicating fetch logic.

export interface AgentOption {
  id: string;
  name: string;
  slug: string;
  description?: string;
}

export interface AgentResponse {
  content: string;
  status: 'success' | 'error';
  error?: string;
  code?: number;
  /** ISO timestamp returned by the backend when the response was served from cache. */
  generatedAt?: string;
  /** True when the backend served the response from cache. */
  fromCache?: boolean;
}

export const fetchAgentsForIntent = async (intent: string): Promise<AgentOption[]> => {
  try {
    const response = await fetch(`/chatbot/agents?intent=${encodeURIComponent(intent)}`);
    if (!response.ok) return [];
    return await response.json();
  } catch {
    return [];
  }
};

/**
 * Decide whether an import connector that declares an `xtm_one_intent` must be
 * treated as unusable ("No agent available") in the import UIs.
 *
 * The intent is only a hard requirement when XTM One is actually configured on
 * the platform. Such connectors keep a legacy (non-XTM One) execution path, so
 * when XTM One is off they remain usable and must NOT be disabled. This mirrors
 * the backend gating in `file-storage.ts`
 * (`connector.xtm_one_intent && xtmOneClient.isConfigured()`).
 *
 * @param xtmOneConfigured tri-state flag from the chatbot config (`null` while loading)
 * @param intent the connector's `xtm_one_intent` (null/undefined for non-AI connectors)
 * @param agentCount number of agents bound to the intent, or `undefined` while not yet loaded
 */
export const isXtmOneIntentWithoutAgents = (
  xtmOneConfigured: boolean | null,
  intent: string | null | undefined,
  agentCount: number | undefined,
): boolean => {
  if (xtmOneConfigured !== true) return false;
  if (!intent) return false;
  if (agentCount === undefined) return false;
  return agentCount === 0;
};

/**
 * Best-effort JSON `{ error }` body extraction for non-OK fetch responses.
 * The chatbot proxy returns `400 { error: '...' }` for body-validation and
 * draft-authorization failures, and `503 { error: '...' }` when XTM One is
 * unreachable — surfacing those messages in the UI is much more actionable
 * than a generic "Bad Request" derived from `response.statusText`. Falls
 * back to `statusText` if the body is not JSON, has no `error` field, or
 * has already been consumed.
 */
const readAgentErrorBody = async (response: Response): Promise<string> => {
  try {
    const data = await response.clone().json();
    if (data && typeof data.error === 'string' && data.error.length > 0) {
      return data.error;
    }
  } catch {
    // Body is not JSON or already consumed — fall through to statusText.
  }
  return `Agent call failed: ${response.statusText}`;
};

export const callAgent = async (agentSlug: string, content: string): Promise<AgentResponse> => {
  const response = await fetch('/chatbot/agent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agent_slug: agentSlug, content }),
  });
  if (!response.ok) {
    return { content: '', status: 'error', error: await readAgentErrorBody(response), code: response.status };
  }
  const data = await response.json();
  return {
    content: data.content ?? '',
    status: data.status ?? 'success',
    error: data.error,
    code: data.code,
  };
};

/**
 * Stream an agent call via SSE. Calls `onChunk` with accumulated content
 * as each text chunk arrives. Returns the final AgentResponse.
 *
 * @param signal - optional AbortSignal to cancel the stream
 * @param forceRefresh - bypass the backend response cache (set when the user
 *   explicitly retries to force a fresh agent execution).
 */
export const callAgentStream = async (
  agentSlug: string,
  content: string,
  onChunk: (partialContent: string) => void,
  signal?: AbortSignal,
  forceRefresh?: boolean,
): Promise<AgentResponse> => {
  const response = await fetch('/chatbot/agent/stream', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agent_slug: agentSlug, content, force_refresh: forceRefresh === true }),
    signal,
  });

  if (!response.ok) {
    return { content: '', status: 'error', error: await readAgentErrorBody(response), code: response.status };
  }

  const reader = response.body?.getReader();
  if (!reader) {
    return { content: '', status: 'error', error: 'No response stream' };
  }

  const decoder = new TextDecoder();
  let accumulated = '';
  let buffer = '';
  let lastError: string | undefined;
  let generatedAt: string | undefined;
  let fromCache = false;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });

      // Parse SSE lines: "data: {...}\n\n"
      const lines = buffer.split('\n');
      // Keep the last potentially incomplete line in the buffer
      buffer = lines.pop() ?? '';

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || !trimmed.startsWith('data: ')) continue;

        try {
          const event = JSON.parse(trimmed.slice(6));
          if (event.type === 'stream' && typeof event.content === 'string') {
            accumulated += event.content;
            onChunk(accumulated);
          } else if (event.type === 'done' && typeof event.content === 'string') {
            // Final message — use authoritative full content
            accumulated = event.content;
            if (typeof event.generated_at === 'string') {
              generatedAt = event.generated_at;
            }
            if (event.cached === true) {
              fromCache = true;
            }
            onChunk(accumulated);
          } else if (event.type === 'error') {
            lastError = event.content ?? 'Unknown error';
          }
          // Ignore status events (thinking, tool_start, etc.)
        } catch {
          // Skip malformed lines
        }
      }
    }
  } finally {
    reader.releaseLock();
  }

  if (lastError) {
    return { content: lastError, status: 'error', error: lastError };
  }
  return { content: accumulated, status: 'success', generatedAt, fromCache };
};
