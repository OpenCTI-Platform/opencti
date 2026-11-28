import { Alert, Button } from '@filigran/design-system';
import { useSchemaGraphStore } from '../../state/schemaGraphStore';

/** Takes the toolbar's place while a path is shown: the display options do not apply to it. */
export const PathBanner = () => {
  const path = useSchemaGraphStore((state) => state.path);
  const types = useSchemaGraphStore((state) => state.schema?.types);
  const clearPath = useSchemaGraphStore((state) => state.clearPath);
  const openFindPath = useSchemaGraphStore((state) => state.openFindPath);
  if (!path) return null;

  const label = (typeId: string) => types?.get(typeId)?.label ?? typeId;
  const hops = path.steps.length;
  return (
    <div className="sv-path-banner">
      <Alert
        severity="info"
        title={`Path from ${label(path.fromTypeId)} to ${label(path.toTypeId)} · ${hops} ${hops === 1 ? 'hop' : 'hops'}`}
        action={(
          <span className="sv-path-banner__actions">
            <Button priority="tertiary" size="sm" onClick={() => openFindPath()}>Edit</Button>
            <Button priority="secondary" size="sm" onClick={clearPath}>Back to canvas</Button>
          </span>
        )}
      />
    </div>
  );
};
