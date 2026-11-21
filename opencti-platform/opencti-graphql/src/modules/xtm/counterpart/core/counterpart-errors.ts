// The user a counterpart lookup runs as: the product applies this user's own rights.
export interface CounterpartCaller {
  id: string;
  user_email: string;
}

/**
 * Why a product gave no answer: not_supported (HTTP 404, the product has no such route, cached
 * per product and route) or unavailable (401, 403, 5xx, timeout, unreadable body: never cached).
 */
export class CounterpartLookupError extends Error {
  reason: 'not_supported' | 'unavailable';

  constructor(reason: 'not_supported' | 'unavailable', message: string) {
    super(message);
    this.name = 'CounterpartLookupError';
    this.reason = reason;
  }
}

/** Maps a failed HTTP call to its reason, without ever carrying the request (its headers hold the token). */
export const lookupErrorOf = (error: any, product: string): CounterpartLookupError => {
  const status = error?.status ?? error?.response?.status;
  if (status === 404) {
    return new CounterpartLookupError('not_supported', `${product} has no such counterpart route`);
  }
  return new CounterpartLookupError('unavailable', `${product} could not answer the counterpart lookup`);
};
