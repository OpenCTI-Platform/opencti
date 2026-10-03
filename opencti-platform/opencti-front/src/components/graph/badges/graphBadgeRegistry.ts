import { useSyncExternalStore } from 'react';
import type { GraphCanvasIcon } from '../utils/graphIcons';
import type { GraphNode } from '../graph.types';

/** Resolved from the theme by the painter, so a badge reads in both themes. */
export type GraphBadgeTone = 'neutral' | 'info' | 'success' | 'warning' | 'error' | 'accent';

export interface GraphBadge {
  /** Stable and unique for the node. */
  key: string;
  /** Drawn on the canvas; a badge without icon is drawn as a dot. */
  icon?: GraphCanvasIcon;
  tone: GraphBadgeTone;
  /** Only a colour carried by the data itself, for example the colour of a marking. */
  color?: string | null;
  /** Translated text, used by the hover card, the accessible list and the export legend. */
  label: string;
  /** Short text drawn in a pill next to the icon, for example a score. */
  value?: string | number;
}

export interface GraphBadgeHelpers {
  t_i18n: (message: string) => string;
}

export interface GraphBadgeProvider {
  /** For example `threat-pulse`. Registering the same id again replaces the provider. */
  id: string;
  /** Lower is drawn first. Built-in providers use 0 to 99. */
  order?: number;
  /**
   * Soft check: read your own fields from `node.raw` (the object received from the query) and
   * return `[]` when they are absent. Never throw, never fetch.
   */
  badgesFor: (node: GraphNode, helpers: GraphBadgeHelpers) => GraphBadge[];
}

const providers = new Map<string, GraphBadgeProvider>();
const listeners = new Set<() => void>();
let version = 0;

const notify = () => {
  version += 1;
  listeners.forEach((listener) => listener());
};

/** Adds a badge provider to every graph; returns the function that removes it. */
export const registerGraphBadgeProvider = (provider: GraphBadgeProvider): (() => void) => {
  providers.set(provider.id, provider);
  notify();
  return () => {
    if (providers.get(provider.id) === provider) {
      providers.delete(provider.id);
      notify();
    }
  };
};

export const graphBadgeProviders = (): GraphBadgeProvider[] => [...providers.values()]
  .sort((a, b) => (a.order ?? 100) - (b.order ?? 100) || a.id.localeCompare(b.id));

/**
 * Every badge of a node, in provider order. A provider that throws is skipped for that node
 * rather than breaking the drawing of the whole graph.
 */
export const badgesOfNode = (node: GraphNode, helpers: GraphBadgeHelpers): GraphBadge[] => graphBadgeProviders()
  .flatMap((provider) => {
    try {
      return provider.badgesFor(node, helpers);
    } catch {
      return [];
    }
  });

const subscribe = (listener: () => void) => {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
};

/** Changes whenever a provider is added or removed, so a graph repaints with the new badges. */
export const useGraphBadgeRegistryVersion = () => useSyncExternalStore(subscribe, () => version, () => version);
