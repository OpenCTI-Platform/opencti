import { useEffect } from 'react';
import { BUILTIN_VIEWS, DEFAULT_VIEW_ID } from '../state/builtinViews';
import { useSchemaGraphStore } from '../state/schemaGraphStore';
import { typeFromHash, typeHash } from '../shared/typeHash';

/**
 * Loads the schema, opens the default view, and keeps the selected type in the URL hash
 * (#type=Malware) so a link to a type can be shared.
 */
export const useAppBootstrap = () => {
  const status = useSchemaGraphStore((state) => state.status);
  const schema = useSchemaGraphStore((state) => state.schema);
  const loadSchema = useSchemaGraphStore((state) => state.loadSchema);

  useEffect(() => {
    if (useSchemaGraphStore.getState().status === 'idle') loadSchema();
  }, [loadSchema]);

  useEffect(() => {
    if (!schema) return;
    const { applySnapshot, focusType } = useSchemaGraphStore.getState();
    const defaultView = BUILTIN_VIEWS.find((view) => view.id === DEFAULT_VIEW_ID);
    if (defaultView) applySnapshot(defaultView.resolve(schema), defaultView.id);
    const linked = typeFromHash();
    if (linked && schema.types.has(linked)) focusType(linked);
  }, [schema]);

  useEffect(() => useSchemaGraphStore.subscribe((state, previous) => {
    if (state.selectedTypeId === previous.selectedTypeId) return;
    const url = state.selectedTypeId
      ? typeHash(state.selectedTypeId)
      : `${window.location.pathname}${window.location.search}`;
    window.history.replaceState(null, '', url);
  }), []);

  useEffect(() => {
    const onHashChange = () => {
      const linked = typeFromHash();
      const { schema: current, selectedTypeId, focusType, navigateToCrumb } = useSchemaGraphStore.getState();
      if (!linked) navigateToCrumb(-1);
      else if (linked !== selectedTypeId && current?.types.has(linked)) focusType(linked);
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  return { status, schema, retry: () => loadSchema() };
};
