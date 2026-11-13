import { Button, Icon, Text } from '@filigran/design-system';
import { useSchemaGraphStore } from '../../state/schemaGraphStore';
import { EmptyState } from '../../shared/ui/EmptyState';

export const CanvasEmptyState = () => {
  const hasPinned = useSchemaGraphStore((state) => state.pinnedTypeIds.length > 0);
  const setPaletteOpen = useSchemaGraphStore((state) => state.setPaletteOpen);
  const setAllCategories = useSchemaGraphStore((state) => state.setAllCategories);

  return (
    <div className="sv-canvas-empty">
      {hasPinned ? (
        <EmptyState icon="sliders-horizontal" title="Everything on the canvas is filtered out">
          <Text variant="content-compact" as="p">The types on the canvas belong to categories that are switched off.</Text>
          <Button onClick={() => setAllCategories(true)}>Show all categories</Button>
        </EmptyState>
      ) : (
        <EmptyState icon="box" title="The canvas is empty">
          <Text variant="content-compact" as="p">Search a type to start exploring, or open a saved view from the sidebar.</Text>
          <Button startIcon={<Icon name="search" size={16} />} onClick={() => setPaletteOpen(true)}>Search a type</Button>
        </EmptyState>
      )}
    </div>
  );
};
