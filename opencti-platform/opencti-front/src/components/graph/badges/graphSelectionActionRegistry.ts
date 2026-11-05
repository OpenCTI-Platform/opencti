import { useSyncExternalStore } from 'react';
import type { GraphCanvasIcon } from '../utils/graphIcons';
import type { GraphLink, GraphNode } from '../graph.types';

/** The selected entities and relationships the action applies to. */
export interface GraphSelection {
  nodes: readonly GraphNode[];
  links: readonly GraphLink[];
}

export interface GraphSelectionAction {
  /** Registering the same id again replaces the action. */
  id: string;
  /** Lower comes first, after the built-in actions of the Selection section of the context menu. */
  order?: number;
  icon: GraphCanvasIcon;
  /** Translated label of the action. */
  label: (t_i18n: (message: string) => string) => string;
  /**
   * Soft check: whether the action applies to this selection on this graph surface (`context` is
   * the one given to `GraphProvider`, `undefined` for container knowledge graphs).
   */
  isAvailable: (selection: GraphSelection, context: string | undefined) => boolean;
  /** Set when the action applies but cannot run now: the menu shows it disabled, saying why. */
  disabledReason?: (selection: GraphSelection, t_i18n: (message: string) => string) => string | undefined;
  /** Run on click when the action has no options. */
  onSelect?: (selection: GraphSelection) => void;
  /**
   * A choice to make first, such as the connector of an enrichment: the context menu opens the
   * items as a submenu and runs `onSelect` with the key of the one picked.
   */
  options?: (selection: GraphSelection, t_i18n: (message: string) => string) => {
    items: { key: string; label: string; section?: string }[];
    onSelect: (key: string) => void;
  } | undefined;
}

const actions = new Map<string, GraphSelectionAction>();
const listeners = new Set<() => void>();
let version = 0;

/** Adds an action to the Selection section of the context menu of every graph; returns the function that removes it. */
export const registerGraphSelectionAction = (action: GraphSelectionAction): (() => void) => {
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

export const graphSelectionActionsFor = (selection: GraphSelection, context: string | undefined): GraphSelectionAction[] => [...actions.values()]
  .filter((action) => {
    try {
      return action.isAvailable(selection, context);
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

export const useGraphSelectionActionRegistryVersion = () => useSyncExternalStore(subscribe, () => version, () => version);
