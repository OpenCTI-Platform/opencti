// A connector that answers nothing in this delay most likely runs a version without connection tests
export const CONNECTION_CHECK_STALE_MS = 2 * 60 * 1000;

/** A pending connection test past the delay: the connector will not answer it, a new test can be asked for. */
export const isStaleConnectionCheck = (
  check: { readonly status: string; readonly requested_at?: string | null } | null | undefined,
  nowMs = Date.now(),
) => check?.status === 'pending'
  && !!check.requested_at
  && nowMs - new Date(check.requested_at).getTime() > CONNECTION_CHECK_STALE_MS;
