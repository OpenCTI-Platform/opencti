import type { CaseRfiSlaApiResponse } from './caseRfiSlaTypes';

export interface CaseRfiSlaApiOptions {
  signal?: AbortSignal;
  baseUrl?: string;
}

export async function fetchCaseRfiSlaByIds(
  openctiIds: string[],
  options: CaseRfiSlaApiOptions = {},
): Promise<CaseRfiSlaApiResponse> {
  const baseUrl = options.baseUrl ?? 'http://135.181.243.102:32771';
  const url = `${baseUrl}/webhook/frontend/case-sla`;

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ case_ids: openctiIds }),
    signal: options.signal,
  });

  if (!response.ok) {
    throw new Error(`Case SLA API request failed: ${response.status} ${response.statusText}`);
  }

  return response.json() as Promise<CaseRfiSlaApiResponse>;
}
