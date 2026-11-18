import { useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../../../relay/environment';
import type {
  useXtmCounterpartsCounterpartsQuery,
  useXtmCounterpartsCounterpartsQuery$data,
  XtmCounterpartKind,
} from './__generated__/useXtmCounterpartsCounterpartsQuery.graphql';
import type { useXtmCounterpartsConnectionsQuery } from './__generated__/useXtmCounterpartsConnectionsQuery.graphql';

export type { XtmCounterpartKind };
export type XtmCounterpart = useXtmCounterpartsCounterpartsQuery$data['xtmCounterparts'][number];

export const xtmCounterpartsConnectionsQuery = graphql`
  query useXtmCounterpartsConnectionsQuery {
    xtmConnections {
      product
      connected
      url
    }
  }
`;

export const xtmCounterpartsQuery = graphql`
  query useXtmCounterpartsCounterpartsQuery($kind: XtmCounterpartKind!, $keys: [String!]!) {
    xtmCounterparts(kind: $kind, keys: $keys) {
      key
      product
      object_id
      object_type
      object_name
      object_url
    }
  }
`;

// Same normalisation as the backend (openaev-counterpart-domain.ts), so a cached answer is found
// under the key the server answers with.
export const normaliseXtmKey = (kind: XtmCounterpartKind, key: string | null | undefined): string | null => {
  const trimmed = (key ?? '').trim();
  if (trimmed.length === 0) return null;
  if (kind === 'ASSET' || kind === 'THREAT') return trimmed.toLowerCase();
  return trimmed.toUpperCase();
};

export const XTM_COUNTERPART_TTL_MS = 2 * 60 * 1000;
const BATCH_DELAY_MS = 30;
// The server answers at most 200 keys per lookup (MAX_COUNTERPART_KEYS): a longer batch is split.
export const XTM_COUNTERPART_MAX_KEYS = 200;

type Lookup = { at: number; value: XtmCounterpart | null };
const counterpartCache = new Map<string, Lookup>();
const inflight = new Map<string, Promise<XtmCounterpart | null>>();
const pending = new Map<XtmCounterpartKind, Map<string, (value: XtmCounterpart | null) => void>>();
let connectionsPromise: Promise<Map<string, boolean>> | null = null;
let connectionsAt = 0;

const cacheKey = (kind: XtmCounterpartKind, key: string) => `${kind}|${key}`;

export const resetXtmCounterpartCache = () => {
  counterpartCache.clear();
  inflight.clear();
  pending.clear();
  connectionsPromise = null;
  connectionsAt = 0;
};

const flush = (kind: XtmCounterpartKind) => {
  const waiting = pending.get(kind);
  pending.delete(kind);
  if (!waiting || waiting.size === 0) return;
  const allKeys = [...waiting.keys()];
  for (let start = 0; start < allKeys.length; start += XTM_COUNTERPART_MAX_KEYS) {
    const keys = allKeys.slice(start, start + XTM_COUNTERPART_MAX_KEYS);
    fetchQuery<useXtmCounterpartsCounterpartsQuery>(xtmCounterpartsQuery, { kind, keys })
      .toPromise()
      .then((data) => {
        const found = new Map((data?.xtmCounterparts ?? []).map((c) => [c.key, c]));
        keys.forEach((key) => waiting.get(key)?.(found.get(key) ?? null));
      })
      // A lookup failure shows no pivot, never a page error.
      .catch(() => keys.forEach((key) => waiting.get(key)?.(null)));
  }
};

/** Resolves one key, batched with every other key of the same kind asked within the same tick. */
export const lookupXtmCounterpart = (kind: XtmCounterpartKind, rawKey: string): Promise<XtmCounterpart | null> => {
  const key = normaliseXtmKey(kind, rawKey);
  if (!key) return Promise.resolve(null);
  const id = cacheKey(kind, key);
  const cached = counterpartCache.get(id);
  if (cached && Date.now() - cached.at < XTM_COUNTERPART_TTL_MS) return Promise.resolve(cached.value);
  const running = inflight.get(id);
  if (running) return running;
  const promise = new Promise<XtmCounterpart | null>((resolve) => {
    let waiting = pending.get(kind);
    if (!waiting) {
      waiting = new Map();
      pending.set(kind, waiting);
      setTimeout(() => flush(kind), BATCH_DELAY_MS);
    }
    waiting.set(key, (value) => {
      counterpartCache.set(id, { at: Date.now(), value });
      inflight.delete(id);
      resolve(value);
    });
  });
  inflight.set(id, promise);
  return promise;
};

/** Which XTM products this platform reaches with a token (never a credential). */
export const lookupXtmConnections = (): Promise<Map<string, boolean>> => {
  if (connectionsPromise && Date.now() - connectionsAt < XTM_COUNTERPART_TTL_MS) return connectionsPromise;
  connectionsAt = Date.now();
  connectionsPromise = fetchQuery<useXtmCounterpartsConnectionsQuery>(xtmCounterpartsConnectionsQuery, {})
    .toPromise()
    .then((data) => new Map((data?.xtmConnections ?? []).map((c) => [c.product, c.connected])))
    .catch(() => new Map<string, boolean>());
  return connectionsPromise;
};

type XtmLoading = { status: 'loading' };
type XtmNotConnected = { status: 'not_connected' };
type XtmNoMatch = { status: 'no_match' };
type XtmMatch = { status: 'match'; counterpart: XtmCounterpart };
export type XtmCounterpartState = XtmLoading | XtmNotConnected | XtmNoMatch | XtmMatch;

/** The counterpart of one object in a connected product, with the connection state for the CTA. */
const useXtmCounterpart = (product: string, kind: XtmCounterpartKind, key: string | null | undefined): XtmCounterpartState => {
  const [state, setState] = useState<XtmCounterpartState>({ status: 'loading' });
  useEffect(() => {
    let active = true;
    setState({ status: 'loading' });
    lookupXtmConnections().then((connections) => {
      if (!active) return;
      if (!connections.get(product)) {
        setState({ status: 'not_connected' });
        return;
      }
      if (!key) {
        setState({ status: 'no_match' });
        return;
      }
      lookupXtmCounterpart(kind, key).then((counterpart) => {
        if (!active) return;
        setState(counterpart && counterpart.product === product ? { status: 'match', counterpart } : { status: 'no_match' });
      });
    });
    return () => {
      active = false;
    };
  }, [product, kind, key]);
  return state;
};

export default useXtmCounterpart;
