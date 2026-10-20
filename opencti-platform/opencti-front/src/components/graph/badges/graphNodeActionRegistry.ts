import { useSyncExternalStore } from 'react';
import type { GraphCanvasIcon } from '../utils/graphIcons';
import type { GraphNode } from '../graph.types';

export interface GraphNodeAction {
  /** Registering the same id again replaces the action. */
  id: string;
  /** Lower comes first, after the built-in actions of the context menu. */
  order?: number;
  icon: GraphCanvasIcon;
  /** Translated label of the action. */
  label: (t_i18n: (message: string) => string) => string;
  /**
   * Soft check: whether the action applies to this node on this graph surface (`context` is the
   * one given to `GraphProvider`, `undefined` for container knowledge graphs).
   */
  isAvailable: (node: GraphNode, context: string | undefined) => boolean;
  /** An in-app path the action opens in a new tab, such as `/dashboard/id/<id>`: the base path of the platform is added. */
  href?: (node: GraphNode) => string;
  /** Run on click when the action is not a link. */
  onSelect?: (node: GraphNode) => void;
  /**
   * A choice to make first, such as the connector of an enrichment: the context menu opens the
   * items as a submenu and runs `onSelect` with the key of the one picked.
   */
  options?: (node: GraphNode, t_i18n: (message: string) => string) => {
    items: { key: string; label: string; section?: string }[];
    onSelect: (key: string) => void;
  } | undefined;
}

const actions = new Map<string, GraphNodeAction>();
const listeners = new Set<() => void>();
let version = 0;

/** Adds an action to the context menu of the nodes of every graph; returns the function that removes it. */
export const registerGraphNodeAction = (action: GraphNodeAction): (() => void) => {
  actions.set(action.id, action);
  version += 1;
  listeners.forEach((listener) => listener());
  return () => {
    if (actions.get(action.id) === action) {
      actions.delete(action.id);
      version += 1;
      listeners.forEach((listener) => listener());
    }
  };
};

export const graphNodeActionsFor = (node: GraphNode, context: string | undefined): GraphNodeAction[] => [...actions.values()]
  .filter((action) => {
    try {
      return action.isAvailable(node, context);
    } catch {
      return false;
    }
  })
  .sort((a, b) => (a.order ?? 100) - (b.order ?? 100) || a.id.localeCompare(b.id));

const subscribe = (listener: () => void) => {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
};

export const useGraphNodeActionRegistryVersion = () => useSyncExternalStore(subscribe, () => version, () => version);
