import { EventSource } from 'eventsource';
import { fetch } from 'undici';
import { UnsupportedError } from '../config/errors';
import { now } from '../utils/format';
import { isEmptyField } from '../database/utils';
import { getPlatformHttpProxyAgent, logApp, TLS_REJECT_UNAUTHORIZED } from '../config/conf';
import { getDestinationCheckedAgent, untilAborted } from '../utils/http-client';
import { checkUrlDestination } from '../utils/internal-destination';
import { getHttpMaxRedirects } from '../http/httpConfig';

// Feel free to migrate to typescript and move inside domain/connector.ts
export const httpBase = (baseUri) => (baseUri.endsWith('/') ? baseUri : `${baseUri}/`);

export const createSyncHttpUri = (sync, state, testMode) => {
  const { uri, stream_id: stream, no_dependencies: dep, listen_deletion: del } = sync;
  if (testMode) {
    logApp.debug(`[OPENCTI] Testing sync url with ${httpBase(uri)}stream/${stream}`);
    return `${httpBase(uri)}stream/${stream}`;
  }
  const from = isEmptyField(state) ? '0-0' : state;
  const recover = sync.recover ?? now();
  let streamUri = `${httpBase(uri)}stream/${stream}?from=${from}&listen-delete=${del}&no-dependencies=${dep}`;
  if (recover) {
    streamUri += `&recover=${recover}`;
  }
  return streamUri;
};

// The remote OpenCTI is a destination configured by users: internal networks are checked like the other synchronizer requests.
// Redirects are followed here, so that each hop is checked and goes through the proxy selected for it.
const SYNC_FEATURE = 'Synchronizer';
const SYNC_REDIRECT_STATUSES = [301, 302, 303, 307, 308];
// Behind a proxy, the destination is resolved before the request: bounded like a connection (undici connect timeout)
export const SYNC_RESOLUTION_TIMEOUT = 10000;
// A DNS resolution cannot be canceled: stop waiting for it when the stream is closed or after SYNC_RESOLUTION_TIMEOUT
const checkSyncDestination = async (url, viaProxy, signal) => {
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(new Error(`Resolution of ${url.hostname} timed out after ${SYNC_RESOLUTION_TIMEOUT}ms`)), SYNC_RESOLUTION_TIMEOUT);
  try {
    const signals = signal ? [signal, timeout.signal] : [timeout.signal];
    await untilAborted(checkUrlDestination(url, SYNC_FEATURE, viaProxy), AbortSignal.any(signals));
  } finally {
    clearTimeout(timer);
  }
};

export const buildSyncFetch = (ssl, token) => {
  return async (url, init) => {
    const requestOrigin = new URL(url).origin;
    const maxRedirects = getHttpMaxRedirects();
    let currentUrl = new URL(url);
    for (let redirectCount = 0; ; redirectCount += 1) {
      const proxyDispatcher = getPlatformHttpProxyAgent(currentUrl.href, true);
      await checkSyncDestination(currentUrl, proxyDispatcher !== undefined, init.signal);
      const dispatcher = proxyDispatcher ?? getDestinationCheckedAgent(ssl, SYNC_FEATURE);
      // The token is only sent to the configured remote OpenCTI, not to another origin it redirects to
      const authorization = !isEmptyField(token) && currentUrl.origin === requestOrigin ? { authorization: `Bearer ${token}` } : {};
      const response = await fetch(currentUrl.href, { ...init, headers: { ...init.headers, ...authorization }, dispatcher, redirect: 'manual' });
      const location = response.headers.get('location');
      if (maxRedirects === 0 || !location || !SYNC_REDIRECT_STATUSES.includes(response.status)) {
        return response;
      }
      await response.body?.cancel();
      if (redirectCount >= maxRedirects) {
        throw new Error('Maximum number of redirects exceeded');
      }
      currentUrl = new URL(location, currentUrl);
    }
  };
};

export const testSync = async (context, user, sync) => {
  const eventSourceUri = createSyncHttpUri(sync, now(), true);
  const { token } = sync;
  const ssl = sync.ssl_verify ?? TLS_REJECT_UNAUTHORIZED;
  return new Promise((resolve, reject) => {
    try {
      const eventSource = new EventSource(eventSourceUri, { fetch: buildSyncFetch(ssl, token) });
      eventSource.addEventListener('connected', (d) => {
        const { connectionId } = JSON.parse(d.data);
        if (connectionId) {
          eventSource.close();
          resolve('Connection success');
        } else {
          eventSource.close();
          reject(UnsupportedError('Server cant generate connection id'));
        }
      });
      eventSource.addEventListener('error', (e) => {
        eventSource.close();
        reject(UnsupportedError(`Cant connect to remote opencti, ${e.message}`));
      });
    } catch (_e) {
      reject(UnsupportedError('Cant connect to remote opencti, check your configuration'));
    }
  });
};
