import { EventSource } from 'eventsource';
import type { ErrorEvent } from 'eventsource';
import { UnsupportedError } from '../config/errors';
import { now } from '../utils/format';
import { isEmptyField } from '../database/utils';
import { getPlatformHttpProxyAgent, logApp } from '../config/conf';
import type {AuthContext, AuthUser} from '../types/user';
import type {SynchronizerAddInput} from '../generated/graphql';

// Feel free to migrate to typescript and move inside domain/connector.ts
export const httpBase = (baseUri: string): string => (baseUri.endsWith('/') ? baseUri : `${baseUri}/`);

export const createSyncHttpUri = (sync: SynchronizerAddInput, state: string, testMode: boolean) => {
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

export const testSync = async (context: AuthContext, user: AuthUser, sync: SynchronizerAddInput) => {
  const eventSourceUri = createSyncHttpUri(sync, now(), true);
  const { token, ssl_verify: _ssl = false } = sync;
  return new Promise((resolve, reject) => {
    try {
      // TODO rejectUnauthorized: ssl,
      const customFetch: typeof fetch = (input, init) => fetch(
        input,
        {
          ...init,
          headers: {
            ...(init?.headers ?? {}),
            ...(!isEmptyField(token) ? { authorization: `Bearer ${token}` } : undefined),
          },
          dispatcher: getPlatformHttpProxyAgent(eventSourceUri, true),
        });
      const eventSource = new EventSource(eventSourceUri, { fetch: customFetch });
      try {
        eventSource.addEventListener('connected', (d: MessageEvent) => {
          const { connectionId } = JSON.parse(d.data);
          if (connectionId) {
            resolve('Connection success');
          } else {
            reject(UnsupportedError('Server cant generate connection id'));
          }
        });
        eventSource.addEventListener('error', (e: ErrorEvent) => {
          reject(UnsupportedError(`Cant connect to remote opencti, ${e.message}`));
        });
      } finally {
        eventSource.close();
      }
    } catch (_e) {
      reject(UnsupportedError('Cant connect to remote opencti, check your configuration'));
    }
  });
};
