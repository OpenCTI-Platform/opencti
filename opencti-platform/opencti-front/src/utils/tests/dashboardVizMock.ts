import { act } from '@testing-library/react';
import { useEffect, useRef, useState } from 'react';

interface DashboardVizArgs {
  dataSelection: unknown[];
  config?: unknown;
  parameters?: unknown;
  buildQueryVariables?: (resolvedDataSelection: never, config: never, parameters?: never) => unknown;
}

interface DashboardVizMockState {
  // Called with the arguments of every render
  dashboardViz: (args: unknown) => void;
  // What the saved filters and variables of the dataset resolve to: the dataset itself when null
  resolvedDataSelection: unknown[] | null;
  // While true, the dataset is being resolved: nothing is queried
  isResolving?: boolean;
}

type QueryRef = { variables: unknown } | null;

// The loads of the mounted widgets, run by loadDashboardViz
const loads = new Set<() => void>();

/**
 * Mock of useDashboardViz reading its resolved dataset from `state`. As the hook, the query built first is loaded
 * at once, and then kept, whatever the next renders build, until loadDashboardViz: a load runs in a transition,
 * the previous query stays until it commits. The query reference is the same object until then.
 * Without variables, while the dataset is resolved or once buildQueryVariables builds none, there is no query,
 * and the next variables built are loaded at once.
 */
export const mockDashboardViz = (state: DashboardVizMockState) => (args: DashboardVizArgs) => {
  state.dashboardViz(args);
  const isResolving = state.isResolving ?? false;
  const resolvedDataSelection = state.resolvedDataSelection ?? args.dataSelection;
  const variables = isResolving
    ? null
    : args.buildQueryVariables?.(resolvedDataSelection as never, (args.config ?? {}) as never, args.parameters as never) ?? null;
  const [queryRef, setQueryRef] = useState<QueryRef>(() => (variables ? { variables } : null));
  if (!variables !== !queryRef) {
    setQueryRef(variables ? { variables } : null);
  }
  const latestVariables = useRef(variables);
  latestVariables.current = variables;
  useEffect(() => {
    const load = () => setQueryRef(latestVariables.current ? { variables: latestVariables.current } : null);
    loads.add(load);
    return () => {
      loads.delete(load);
    };
  }, []);
  return {
    renderGuards: { isMissingHostEntity: false, isMissingSavedFilters: false, hasUnresolvedVariables: false },
    isPreviewMode: false,
    queryRef: variables ? queryRef : null,
    resolvedDataSelection,
    isResolving,
    skipped: !isResolving && !!args.buildQueryVariables && !variables,
  };
};

/**
 * Commits a load of the mounted widgets: each one gets a new query reference, of the variables it built last.
 */
export const loadDashboardViz = () => act(() => loads.forEach((load) => load()));
