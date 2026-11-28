import { useMemo } from 'react';
import { useShallow } from 'zustand/react/shallow';
import type { NormalizedSchema } from '../../data/schemaTypes';
import { resolveBuiltinViews, type SavedView } from '../../state/builtinViews';
import { type CanvasSnapshot, sameSnapshot } from '../../state/canvasSnapshot';
import { useSavedViewsStore } from '../../state/savedViewsStore';
import { useSchemaGraphStore } from '../../state/schemaGraphStore';

const useCurrentSnapshot = (): CanvasSnapshot => useSchemaGraphStore(useShallow((state) => ({
  pinnedTypeIds: state.pinnedTypeIds,
  expandedTypeIds: state.expandedTypeIds,
  revealedRelations: state.revealedRelations,
  enabledCategories: state.enabledCategories,
  showInheritance: state.showInheritance,
  showRelations: state.showRelations,
  includeRefs: state.includeRefs,
  direction: state.direction,
})));

export const useSavedViews = (schema: NormalizedSchema) => {
  const builtinViews = useMemo(() => resolveBuiltinViews(schema), [schema]);
  const userViews = useSavedViewsStore((state) => state.views);
  const { addView, renameView, updateView, removeView } = useSavedViewsStore(useShallow((state) => ({
    addView: state.addView,
    renameView: state.renameView,
    updateView: state.updateView,
    removeView: state.removeView,
  })));
  const activeViewId = useSchemaGraphStore((state) => state.activeViewId);
  const applySnapshot = useSchemaGraphStore((state) => state.applySnapshot);
  const current = useCurrentSnapshot();

  const views = useMemo(() => [...builtinViews, ...userViews], [builtinViews, userViews]);
  const activeView = views.find((view) => view.id === activeViewId) ?? null;
  const isModified = activeView !== null && !sameSnapshot(activeView.snapshot, current);

  return {
    views,
    activeView,
    isModified,
    applyView: (view: SavedView) => applySnapshot(view.snapshot, view.id),
    saveAsNew: (name: string) => {
      const id = addView(name, current);
      useSchemaGraphStore.setState({ activeViewId: id });
    },
    saveActive: () => {
      if (activeView && !activeView.builtin) updateView(activeView.id, current);
    },
    renameView,
    removeView: (id: string) => {
      removeView(id);
      if (id === activeViewId) useSchemaGraphStore.setState({ activeViewId: null });
    },
  };
};
