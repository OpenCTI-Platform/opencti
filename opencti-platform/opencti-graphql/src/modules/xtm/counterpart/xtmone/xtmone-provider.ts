import { type CounterpartProvider, counterpartsOfAnswer } from '../core/counterpart-domain';
import { fetchXtmOneAssets, getXtmOneUrl, isXtmOneConnected } from './xtmone-client';

// XTM One's inventory holds assets only (hostnames, FQDNs, IP addresses): every other kind is
// not_supported, so nothing is drawn for it.
export const xtmOneProvider: CounterpartProvider = {
  product: 'xtmone',
  url: getXtmOneUrl,
  isConnected: isXtmOneConnected,
  supports: (kind) => kind === 'ASSET',
  // XTM One echoes the key as asked; normalised back like the other products.
  resolve: async (kind, keys, caller) => counterpartsOfAnswer('xtmone', kind, keys, await fetchXtmOneAssets(keys, caller)),
};
