import { useSyncExternalStore } from 'react';
import type { GraphCanvasIcon } from '../utils/graphIcons';
import type { GraphNode } from '../graph.types';

/** Resolved from the theme by the painter, so a badge reads in both themes. */
export type GraphBadgeTone = 'neutral' | 'info' | 'success' | 'warning' | 'error' | 'accent';

export interface GraphBadge {
  /** Stable among the badges of its provider; `badgesOfNode` prefixes it with the provider id. */
  key: string;
  /** Drawn on the canvas; a badge without icon is drawn as a dot. */
  icon?: GraphCanvasIcon;
  tone: GraphBadgeTone;
  /** Only a colour carried by the data itself, for example the colour of a marking. */
  color?: string | null;
  /** Translated text, used by the hover card, the accessible list and the export legend. */
  label: string;
  /** Translated sentence saying what the badge means, the tooltip of the hover card (the label when absent). */
  tooltip?: string;
  /** Translated name of the legend entry, when the label is specific to the node (the legend uses the label when absent). */
  legendLabel?: string;
  /** Short text drawn in a pill next to the icon, for example a score. */
  value?: string | number;
}

export interface GraphBadgeHelpers {
  t_i18n: (message: string, options?: { values?: Record<string, string | number> }) => string;
}

export interface GraphBadgeProvider {
  /** For example `threat-pulse`. Registering the same id again replaces the provider. */
  id: string;
  /** Among badges of the same tone, lower is drawn first. Built-in providers use 0 to 99. */
  order?: number;
  /**
   * Soft check: read your own fields from `node.raw` (the object received from the query) and
   * return `[]` when they are absent. Never throw, never fetch. At most one badge per node: when
   * several are returned, only the most severe is kept.
   */
  badgesFor: (node: GraphNode, helpers: GraphBadgeHelpers) => GraphBadge[];
}

/** Badges drawn on a node at most; the others are counted in a "+N" marker and listed in the hover card. */
export const MAX_DRAWN_BADGES = 3;

/** Most severe first, so that a failed or blocking state is never the badge left out. */
const TONE_SEVERITY: Record<GraphBadgeTone, number> = { error: 0, warning: 1, accent: 2, info: 3, success: 4, neutral: 5 };
const bySeverity = (a: GraphBadge, b: GraphBadge) => TONE_SEVERITY[a.tone] - TONE_SEVERITY[b.tone];

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
 * Every badge of a node, one per provider, the most severe first and in provider order within a
 * tone. Its key is prefixed with the provider id, so two providers using the same key stay apart
 * in the legend and the hover card. A provider that throws is skipped for that node rather than
 * breaking the drawing of the whole graph.
 */
export const badgesOfNode = (node: GraphNode, helpers: GraphBadgeHelpers): GraphBadge[] => graphBadgeProviders()
  .flatMap((provider) => {
    try {
      const [mostSevere] = [...provider.badgesFor(node, helpers)].sort(bySeverity);
      return mostSevere ? [{ ...mostSevere, key: `${provider.id}:${mostSevere.key}` }] : [];
    } catch {
      return [];
    }
  })
  .sort(bySeverity);

/** The badges drawn on the canvas and the number left for the "+N" marker. */
export const drawnBadges = (badges: readonly GraphBadge[]): { drawn: GraphBadge[]; more: number } => ({
  drawn: badges.slice(0, MAX_DRAWN_BADGES),
  more: Math.max(0, badges.length - MAX_DRAWN_BADGES),
});

const subscribe = (listener: () => void) => {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
};

/** Changes whenever a provider is added or removed, so a graph repaints with the new badges. */
export const useGraphBadgeRegistryVersion = () => useSyncExternalStore(subscribe, () => version, () => version);
