import { EventSource } from 'eventsource';
import { Agent } from 'undici';
import { UnsupportedError } from '../config/errors';
import { now } from '../utils/format';
import { isEmptyField } from '../database/utils';
import { getPlatformHttpProxyAgent, logApp } from '../config/conf';

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

// Only needed when ssl_verify is disabled: with it enabled, undici's default dispatcher already
// rejects unauthorized certificates, so no custom agent is required.
const insecureAgent = new Agent({ connect: { rejectUnauthorized: false } });

const buildSyncFetch = (eventSourceUri, ssl, token) => {
  const dispatcher = getPlatformHttpProxyAgent(eventSourceUri, true) ?? (ssl ? undefined : insecureAgent);
  const headers = !isEmptyField(token) ? { authorization: `Bearer ${token}` } : undefined;
  return (url, init) => fetch(url, { ...init, headers: { ...init.headers, ...headers }, dispatcher });
};

export const testSync = async (context, user, sync) => {
  const eventSourceUri = createSyncHttpUri(sync, now(), true);
  const { token, ssl_verify: ssl = false } = sync;
  return new Promise((resolve, reject) => {
    try {
      const eventSource = new EventSource(eventSourceUri, { fetch: buildSyncFetch(eventSourceUri, ssl, token) });
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
