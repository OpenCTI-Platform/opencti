import { useMemo } from 'react';
import { useShallow } from 'zustand/react/shallow';
import type { NormalizedSchema } from '../../data/schemaTypes';
import { useSchemaGraphStore } from '../../state/schemaGraphStore';
import { buildVisibleGraph, type GraphScope, type VisibleGraph } from './buildVisibleGraph';

export const useGraphScope = (): GraphScope => useSchemaGraphStore(useShallow((state) => ({
  pinnedTypeIds: state.pinnedTypeIds,
  expandedTypeIds: state.expandedTypeIds,
  revealedRelations: state.revealedRelations,
  enabledCategories: state.enabledCategories,
  showInheritance: state.showInheritance,
  showRelations: state.showRelations,
  includeRefs: state.includeRefs,
  path: state.path,
})));

/** The visible graph, recomputed only when the scope itself changes (not on selection or camera moves). */
export const useVisibleGraph = (schema: NormalizedSchema): VisibleGraph => {
  const scope = useGraphScope();
  return useMemo(() => buildVisibleGraph(schema, scope), [schema, scope]);
};
