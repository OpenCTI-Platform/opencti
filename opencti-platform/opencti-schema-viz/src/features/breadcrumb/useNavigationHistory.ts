import { useEffect } from 'react';
import { useSchemaGraphStore } from '../../state/schemaGraphStore';

export interface Crumb {
  typeId: string;
  label: string;
  index: number;
}

/** Breadcrumb of visited types; Alt+← goes back one step, like GraphQL Voyager. */
export const useNavigationHistory = () => {
  const history = useSchemaGraphStore((state) => state.history);
  const types = useSchemaGraphStore((state) => state.schema?.types);
  const selectedTypeId = useSchemaGraphStore((state) => state.selectedTypeId);
  const navigateToCrumb = useSchemaGraphStore((state) => state.navigateToCrumb);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (!event.altKey || event.key !== 'ArrowLeft') return;
      const { history: current } = useSchemaGraphStore.getState();
      if (current.length > 1) {
        event.preventDefault();
        navigateToCrumb(current.length - 2);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [navigateToCrumb]);

  const crumbs: Crumb[] = history.map((typeId, index) => ({ typeId, label: types?.get(typeId)?.label ?? typeId, index }));
  return { crumbs, selectedTypeId };
};
