import type { RawQueryRequest, RawQueryResponse } from './mockRessaSearchApi';

export interface RawQueryApiOptions {
  signal?: AbortSignal;
  baseUrl?: string;
}

export const RESSA_SEARCH_API_BASE_URL = 'http://135.181.243.102:5080';

const normalizeBaseUrl = (baseUrl?: string) => {
  if (!baseUrl) return '';
  return baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
};

const defaultBaseUrl = () => {
  // In browser, prefer same-origin + dev proxy to avoid CORS issues.
  // In non-browser environments, use the explicit base URL.
  if (typeof window !== 'undefined') return '';
  return RESSA_SEARCH_API_BASE_URL;
};

const buildRawQueryUrl = (baseUrl: string, request: RawQueryRequest) => {
  const params = new URLSearchParams();
  params.set('maxRelationDepth', String(request.maxRelationDepth ?? 20));
  params.set('maxPrimaryDocuments', String(request.maxPrimaryDocuments ?? 20));
  params.set('maxRelatedEntities', String(request.maxRelatedEntities ?? 20));
  params.set('maxRelationships', String(request.maxRelationships ?? 20));
  params.set('maxRelatedDocuments', String(request.maxRelatedDocuments ?? 20));
  params.set('includeRelationshipDocuments', String(request.includeRelationshipDocuments ?? true));
  params.set('includeNestedObjects', String(request.includeNestedObjects ?? true));
  params.set('includeMetadataAndHistory', String(request.includeMetadataAndHistory ?? true));
  params.set('multilineOutput', String(request.multilineOutput ?? true));

  const prefix = baseUrl ? `${baseUrl}` : '';
  return `${prefix}/api/opencti/query/raw?${params.toString()}`;
};

export async function rawQueryApi(
  request: RawQueryRequest,
  options: RawQueryApiOptions = {},
): Promise<RawQueryResponse> {
  const baseUrl = normalizeBaseUrl(options.baseUrl ?? defaultBaseUrl());

  const url = buildRawQueryUrl(baseUrl, request);
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'Content-Type': 'text/plain',
    },
    body: request.query,
    signal: options.signal,
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Request failed (${res.status}): ${text || res.statusText}`);
  }

  return (await res.json()) as RawQueryResponse;
}
