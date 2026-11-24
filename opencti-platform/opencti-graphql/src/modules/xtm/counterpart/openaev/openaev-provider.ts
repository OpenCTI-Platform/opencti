import { type CounterpartKind, type CounterpartProvider, counterpartsOfAnswer, registerCounterpartProvider } from '../core/counterpart-domain';
import { fetchOpenAevObjects, getOpenAevUrl, isOpenAevConnected, type OpenAevObjectPath } from './openaev-client';

// OpenAEV's lookup route per kind: OpenAEV holds every kind OpenCTI sends.
const OPENAEV_PATHS: Record<CounterpartKind, OpenAevObjectPath> = {
  ASSET: 'assets',
  ATTACK_PATTERN: 'attack-patterns',
  VULNERABILITY: 'vulnerabilities',
  THREAT: 'threats',
  ALERT: 'alerts',
};

export const openAevProvider: CounterpartProvider = {
  product: 'openaev',
  url: getOpenAevUrl,
  isConnected: isOpenAevConnected,
  supports: (kind) => kind in OPENAEV_PATHS,
  resolve: async (kind, keys, caller) => counterpartsOfAnswer('openaev', kind, keys, await fetchOpenAevObjects(OPENAEV_PATHS[kind], keys, caller)),
};

registerCounterpartProvider(openAevProvider);
