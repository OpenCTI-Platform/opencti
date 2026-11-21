import { useSchemaGraphStore } from '../../../state/schemaGraphStore';

/** Each node subscribes to its own flag only, so expanding one node re-renders that node alone. */
export const useNodeExpansion = (typeId: string) => {
  const isExpanded = useSchemaGraphStore((state) => state.expandedTypeIds.includes(typeId));
  const toggleExpand = useSchemaGraphStore((state) => state.toggleExpand);
  return { isExpanded, toggle: () => toggleExpand(typeId) };
};

export const useIsSelected = (typeId: string) => useSchemaGraphStore((state) => state.selectedTypeId === typeId);
