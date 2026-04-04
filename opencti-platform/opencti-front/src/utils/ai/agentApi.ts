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

export const callAgent = async (agentSlug: string, content: string): Promise<AgentResponse> => {
  const response = await fetch('/chatbot/agent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agent_slug: agentSlug, content }),
  });
  if (!response.ok) {
    return { content: '', status: 'error', error: `Agent call failed: ${response.statusText}`, code: response.status };
  }
  const data = await response.json();
  return {
    content: data.content ?? '',
    status: data.status ?? 'success',
    error: data.error,
    code: data.code,
  };
};
