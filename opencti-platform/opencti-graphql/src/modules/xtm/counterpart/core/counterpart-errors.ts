// The user a counterpart lookup runs as: the product applies this user's own rights.
export interface CounterpartCaller {
  id: string;
  user_email: string;
}

/**
 * Why a product gave no answer: not_supported (HTTP 404, the product has no such route, cached
 * per product and route for the TTL), forbidden (HTTP 403, this user has no right to read that
 * kind there: draws nothing, cached for this user only for the TTL) or unavailable (401, 5xx,
 * timeout, unreadable body: an outage, never cached).
 */
export type CounterpartLookupReason = 'not_supported' | 'forbidden' | 'unavailable';

export class CounterpartLookupError extends Error {
  reason: CounterpartLookupReason;

  constructor(reason: CounterpartLookupReason, message: string) {
    super(message);
    this.name = 'CounterpartLookupError';
    this.reason = reason;
  }
}

/**
 * Maps a failed HTTP call to its reason, without ever carrying the request (its headers hold the token).
 * forbiddenIsPerUser false: a 403 is not about the user (a product that authenticates the lookup with a
 * service account, as OpenCRQ does), so it is an outage of the connection, never cached per user.
 */
export const lookupErrorOf = (error: any, product: string, { forbiddenIsPerUser = true }: { forbiddenIsPerUser?: boolean } = {}): CounterpartLookupError => {
  const status = error?.status ?? error?.response?.status;
  if (status === 404) {
    return new CounterpartLookupError('not_supported', `${product} has no such counterpart route`);
  }
  if (status === 403 && forbiddenIsPerUser) {
    return new CounterpartLookupError('forbidden', `${product} does not let this user read that kind`);
  }
  return new CounterpartLookupError('unavailable', `${product} could not answer the counterpart lookup`);
};

/**
 * The reason of a failed lookup, logged once by the client only when it is an outage: 404 and 403 are
 * left to the domain (one warning per route per process, no warning on a per-user 403).
 */
export const lookupFailureOf = (
  error: any,
  product: string,
  log: (message: string, meta: Record<string, unknown>) => void,
  options?: { forbiddenIsPerUser?: boolean },
): CounterpartLookupError => {
  const failure = lookupErrorOf(error, product, options);
  if (failure.reason === 'unavailable') {
    // Never log the request: its headers carry the user's token.
    log(`[${product}] Counterpart lookup failed`, { status: error?.status ?? error?.response?.status, code: error?.code });
  }
  return failure;
};
