import { useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../../../../../relay/environment';
import useHelper from '../../../../../../utils/hooks/useHelper';
import type { useXtmCounterpartsOfQuery, useXtmCounterpartsOfQuery$data } from './__generated__/useXtmCounterpartsOfQuery.graphql';
import type { useXtmCounterpartsConnectionsQuery } from './__generated__/useXtmCounterpartsConnectionsQuery.graphql';

export type XtmCounterpartResult = useXtmCounterpartsOfQuery$data['xtmCounterpartsOf'][number];
export type XtmCounterpart = NonNullable<XtmCounterpartResult['counterpart']>;

export const xtmCounterpartsConnectionsQuery = graphql`
  query useXtmCounterpartsConnectionsQuery {
    xtmConnections {
      product
      connected
    }
  }
`;

export const xtmCounterpartsOfQuery = graphql`
  query useXtmCounterpartsOfQuery($ids: [String!]!) {
    xtmCounterpartsOf(ids: $ids) {
      # Aliased: the id is the OpenCTI object's own id, so Relay must not normalise this result
      # into that object's record (it would overwrite its __typename and break the page).
      source_id: id
      product
      status
      counterpart {
        key
        product
        object_id
        object_type
        object_name
        object_url
        facts {
          key
          value
        }
      }
    }
  }
`;

// Dedicated feature flag, off by default (Sam, 23 Nov 2026): it gates the emblem, its surface, the
// list row marks and every counterpart call. Same id as on the server (XTM_COUNTERPARTS_FEATURE_FLAG).
export const XTM_COUNTERPARTS_FEATURE_FLAG = 'XTM_COUNTERPARTS';

export const useXtmCounterpartsEnabled = (): boolean => {
  const { isFeatureEnable } = useHelper();
  return isFeatureEnable(XTM_COUNTERPARTS_FEATURE_FLAG);
};

export const XTM_COUNTERPART_TTL_MS = 2 * 60 * 1000;
const BATCH_DELAY_MS = 30;
// The server answers at most 200 ids per lookup (MAX_COUNTERPART_IDS): a longer batch is split.
export const XTM_COUNTERPART_MAX_IDS = 200;

// The answer for one OpenCTI object: one result per connected product, keyed by product. An object
// the server gave no entry for (unreadable, or no key to match on) has an empty map: nothing is drawn.
export type XtmCounterpartAnswer = ReadonlyMap<string, XtmCounterpartResult>;
// A lookup that failed as a whole (network, server error): every product is unavailable for it.
export const XTM_LOOKUP_FAILED = 'failed' as const;
type Lookup = XtmCounterpartAnswer | typeof XTM_LOOKUP_FAILED;

const counterpartCache = new Map<string, { at: number; value: XtmCounterpartAnswer }>();
const inflight = new Map<string, Promise<Lookup>>();
let pending: Map<string, (value: Lookup) => void> | null = null;
let connections: { at: number; promise: Promise<Map<string, boolean> | null> } | null = null;

export const resetXtmCounterpartCache = () => {
  counterpartCache.clear();
  inflight.clear();
  pending = null;
  connections = null;
};

const flush = () => {
  const waiting = pending;
  pending = null;
  if (!waiting || waiting.size === 0) return;
  const allIds = [...waiting.keys()];
  for (let start = 0; start < allIds.length; start += XTM_COUNTERPART_MAX_IDS) {
    const ids = allIds.slice(start, start + XTM_COUNTERPART_MAX_IDS);
    fetchQuery<useXtmCounterpartsOfQuery>(xtmCounterpartsOfQuery, { ids })
      .toPromise()
      .then((data) => {
        const byId = new Map<string, Map<string, XtmCounterpartResult>>();
        (data?.xtmCounterpartsOf ?? []).forEach((result) => {
          const answer = byId.get(result.source_id) ?? new Map<string, XtmCounterpartResult>();
          answer.set(result.product, result);
          byId.set(result.source_id, answer);
        });
        ids.forEach((id) => waiting.get(id)?.(byId.get(id) ?? new Map()));
      })
      // A lookup failure is a muted "unavailable", never a page error and never cached.
      .catch(() => ids.forEach((id) => waiting.get(id)?.(XTM_LOOKUP_FAILED)));
  }
};

/**
 * The counterparts of one OpenCTI object in every connected product, batched with every other
 * object asked within the same tick (whatever its type: the server reads each object's key under
 * the caller's rights). Found and not found answers are cached for the TTL; an answer holding an
 * unavailable product, or a failed lookup, is not.
 */
export const lookupXtmCounterpartsOf = (id: string): Promise<Lookup> => {
  const cached = counterpartCache.get(id);
  if (cached && Date.now() - cached.at < XTM_COUNTERPART_TTL_MS) return Promise.resolve(cached.value);
  const running = inflight.get(id);
  if (running) return running;
  const promise = new Promise<Lookup>((resolve) => {
    if (!pending) {
      pending = new Map();
      setTimeout(flush, BATCH_DELAY_MS);
    }
    pending.set(id, (value) => {
      inflight.delete(id);
      const cacheable = value !== XTM_LOOKUP_FAILED && ![...value.values()].some((r) => r.status === 'unavailable');
      if (cacheable) counterpartCache.set(id, { at: Date.now(), value });
      resolve(value);
    });
  });
  inflight.set(id, promise);
  return promise;
};

/**
 * Which XTM products this platform reaches (never a credential or an address), or null when the
 * query failed: a failure is never cached, so it never reads as "not connected".
 */
export const lookupXtmConnections = (): Promise<Map<string, boolean> | null> => {
  if (connections && Date.now() - connections.at < XTM_COUNTERPART_TTL_MS) return connections.promise;
  const entry = {
    at: Date.now(),
    promise: fetchQuery<useXtmCounterpartsConnectionsQuery>(xtmCounterpartsConnectionsQuery, {})
      .toPromise()
      .then((data) => new Map((data?.xtmConnections ?? []).map((c) => [c.product, c.connected])))
      .catch(() => {
        if (connections === entry) connections = null;
        return null;
      }),
  };
  connections = entry;
  return entry.promise;
};

type XtmLoading = { status: 'loading' };
// Nothing to draw: no key to match on, the object is not readable, or the product has no such lookup.
type XtmNone = { status: 'none' };
type XtmNotConnected = { status: 'not_connected' };
type XtmUnavailable = { status: 'unavailable' };
type XtmNoMatch = { status: 'no_match' };
type XtmMatch = { status: 'match'; counterpart: XtmCounterpart };
export type XtmCounterpartState = XtmLoading | XtmNone | XtmNotConnected | XtmUnavailable | XtmNoMatch | XtmMatch;

/** The state one product's answer gives for one object. */
export const xtmCounterpartStateOf = (lookup: Lookup, product: string): XtmCounterpartState => {
  if (lookup === XTM_LOOKUP_FAILED) return { status: 'unavailable' };
  const result = lookup.get(product);
  if (!result) return { status: 'none' };
  switch (result.status) {
    case 'found':
      return result.counterpart ? { status: 'match', counterpart: result.counterpart } : { status: 'no_match' };
    case 'not_found':
      return { status: 'no_match' };
    case 'unavailable':
      return { status: 'unavailable' };
    default:
      return { status: 'none' };
  }
};

export type XtmCounterpartStates = Readonly<Record<string, XtmCounterpartState>>;

const statesOf = (products: ReadonlyArray<string>, state: XtmCounterpartState): XtmCounterpartStates => (
  Object.fromEntries(products.map((product) => [product, state]))
);

/**
 * The counterparts of one OpenCTI object in several products, from one connections read and one
 * batched lookup. Behind the dedicated feature flag XTM_COUNTERPARTS: while it is off, every
 * product is 'none' and nothing is sent (the server refuses the lookup too).
 */
export const useXtmCounterpartStates = (products: ReadonlyArray<string>, objectId: string | null | undefined): XtmCounterpartStates => {
  const enabled = useXtmCounterpartsEnabled();
  const productsKey = products.join(',');
  const [states, setStates] = useState<XtmCounterpartStates>(() => statesOf(products, { status: enabled ? 'loading' : 'none' }));
  useEffect(() => {
    const keys = productsKey ? productsKey.split(',') : [];
    let active = true;
    if (!enabled || keys.length === 0) {
      setStates(statesOf(keys, { status: 'none' }));
      return () => {
        active = false;
      };
    }
    setStates(statesOf(keys, { status: 'loading' }));
    lookupXtmConnections().then((connected) => {
      if (!active) return;
      if (!connected) {
        setStates(statesOf(keys, { status: 'unavailable' }));
        return;
      }
      const reachable = keys.filter((key) => connected.get(key));
      const unreachable: Array<[string, XtmCounterpartState]> = keys.filter((key) => !connected.get(key)).map((key) => [key, { status: 'not_connected' }]);
      if (reachable.length === 0 || !objectId) {
        setStates(Object.fromEntries([...unreachable, ...reachable.map((key): [string, XtmCounterpartState] => [key, { status: 'none' }])]));
        return;
      }
      lookupXtmCounterpartsOf(objectId).then((lookup) => {
        if (!active) return;
        setStates(Object.fromEntries([...unreachable, ...reachable.map((key): [string, XtmCounterpartState] => [key, xtmCounterpartStateOf(lookup, key)])]));
      });
    });
    return () => {
      active = false;
    };
  }, [enabled, productsKey, objectId]);
  return states;
};

/** The counterpart of one OpenCTI object in one connected product, with the connection state for the CTA. */
const useXtmCounterpart = (product: string, objectId: string | null | undefined): XtmCounterpartState => {
  const states = useXtmCounterpartStates([product], objectId);
  return states[product] ?? { status: 'loading' };
};

export default useXtmCounterpart;
