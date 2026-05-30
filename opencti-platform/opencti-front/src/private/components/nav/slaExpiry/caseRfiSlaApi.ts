import type { CaseRfiSlaApiResponse } from './caseRfiSlaTypes';
import mockCaseRfiSlaResponse from './mockCaseRfiSlaResponse.json';

export interface CaseRfiSlaApiOptions {
  signal?: AbortSignal;
  baseUrl?: string;
}

const MOCK_RESPONSE = mockCaseRfiSlaResponse as CaseRfiSlaApiResponse;

const filterMockResults = (openctiIds: string[]): CaseRfiSlaApiResponse => {
  if (openctiIds.length === 0) {
    return MOCK_RESPONSE;
  }

  const matching = MOCK_RESPONSE.results.filter((result) => openctiIds.includes(result.opencti_id));
  return {
    results: matching.length > 0 ? matching : MOCK_RESPONSE.results,
  };
};

export async function fetchCaseRfiSlaByIds(
  openctiIds: string[],
  _options: CaseRfiSlaApiOptions = {},
): Promise<CaseRfiSlaApiResponse> {
  // TODO: replace with real endpoint once available.
  await new Promise((resolve) => {
    setTimeout(resolve, 0);
  });
  return filterMockResults(openctiIds);
}
