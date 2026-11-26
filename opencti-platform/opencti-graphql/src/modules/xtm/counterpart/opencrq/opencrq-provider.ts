import { type CounterpartKind, type CounterpartProvider, counterpartsOfAnswer } from '../core/counterpart-domain';
import { fetchOpenCrqObjects, getOpenCrqUrl, isOpenCrqConnected, type OpenCrqLookupKind } from './opencrq-client';

// OpenCRQ holds threats (STIX id), vulnerabilities (CVE) and assets (hostname); attack patterns and
// alerts have no OpenCRQ counterpart (not_supported: nothing is drawn).
const OPENCRQ_KINDS: ReadonlySet<CounterpartKind> = new Set<OpenCrqLookupKind>(['THREAT', 'VULNERABILITY', 'ASSET']);

export const openCrqProvider: CounterpartProvider = {
  product: 'opencrq',
  url: getOpenCrqUrl,
  isConnected: isOpenCrqConnected,
  supports: (kind) => OPENCRQ_KINDS.has(kind),
  // OpenCRQ answers keys in its own case (STIX ids and hostnames lower, CVEs upper): normalised back.
  resolve: async (kind, keys, caller) => counterpartsOfAnswer('opencrq', kind, keys, await fetchOpenCrqObjects(kind as OpenCrqLookupKind, keys, caller)),
};
