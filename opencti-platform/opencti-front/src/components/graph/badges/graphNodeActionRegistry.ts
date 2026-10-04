import { useSyncExternalStore } from 'react';
import type { GraphCanvasIcon } from '../utils/graphIcons';
import type { GraphNode } from '../graph.types';

export interface GraphNodeAction {
  /** Registering the same id again replaces the action. */
  id: string;
  /** Lower comes first, after the built-in actions of the hover card. */
  order?: number;
  icon: GraphCanvasIcon;
  /** Translated label of the action. */
  label: (t_i18n: (message: string) => string) => string;
  /**
   * Soft check: whether the action applies to this node on this graph surface (`context` is the
   * one given to `GraphProvider`, `undefined` for container knowledge graphs).
   */
  isAvailable: (node: GraphNode, context: string | undefined) => boolean;
  /** An in-app path the action opens. */
  href?: (node: GraphNode) => string;
  /** Run on click when the action is not a link. */
  onSelect?: (node: GraphNode) => void;
}

const actions = new Map<string, GraphNodeAction>();
const listeners = new Set<() => void>();
let version = 0;

/** Adds a quick action to the node hover card of every graph; returns the function that removes it. */
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
