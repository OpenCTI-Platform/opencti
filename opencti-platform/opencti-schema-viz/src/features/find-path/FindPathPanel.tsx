import { Alert, Button, Chip, Icon, Paper, Switch, Text } from '@filigran/design-system';
import { useEffect, useRef } from 'react';
import type { NormalizedSchema, SchemaPath } from '../../data/schemaTypes';
import { useSchemaGraphStore } from '../../state/schemaGraphStore';
import { IconAction } from '../../shared/ui/IconAction';
import { isPopoverOpen } from '../../shared/ui/overlays';
import { TypeLink } from '../node-inspector/TypeLink';
import { TypeCombobox } from '../search/TypeCombobox';
import { useFindPath } from './useFindPath';
import './findPath.css';

const PathSteps = ({ schema, path }: { schema: NormalizedSchema; path: SchemaPath }) => (
  <ol className="sv-path-steps">
    {path.typeIds.map((typeId, index) => {
      const type = schema.types.get(typeId);
      const step = path.steps[index];
      const relation = step ? schema.relations.get(step.relationId) : undefined;
      const via = step?.viaTypeId ? schema.types.get(step.viaTypeId) : undefined;
      return (
        <li key={`${typeId}-${index}`}>
          {type && <TypeLink type={type} chip />}
          {relation && (
            <div className="sv-path-steps__relation">
              <Icon name={step.direction === 'out' ? 'arrow-down' : 'arrow-up'} size={16} className="sv-muted" />
              <Text variant="content-code" as="span">{relation.name}</Text>
              {relation.kind === 'ref' && <Chip label="Ref" severity="low" />}
              {step.direction === 'in' && <Text variant="content-caption" as="span" className="sv-faint">reversed</Text>}
              {via && <Text variant="content-caption" as="span" className="sv-faint">via {via.label}</Text>}
            </div>
          )}
        </li>
      );
    })}
  </ol>
);

/** "Path between two types", inspired by Azimutt: breadth-first search over the schema relations. */
export const FindPathPanel = ({ schema }: { schema: NormalizedSchema }) => {
  const findPath = useSchemaGraphStore((state) => state.findPath);
  const setFindPath = useSchemaGraphStore((state) => state.setFindPath);
  const closeFindPath = useSchemaGraphStore((state) => state.closeFindPath);
  const showPath = useSchemaGraphStore((state) => state.showPath);
  const result = useFindPath(schema, findPath.fromTypeId, findPath.toTypeId, findPath.options);
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => event.key === 'Escape' && !isPopoverOpen() && closeFindPath();
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as HTMLElement;
      // Combobox panels are portalled out of the panel, so they count as inside.
      if (!panelRef.current?.contains(target) && !target.closest('[data-find-path-trigger], [data-radix-popper-content-wrapper]')) closeFindPath();
    };
    window.addEventListener('keydown', onKeyDown, { capture: true });
    window.addEventListener('pointerdown', onPointerDown);
    return () => {
      window.removeEventListener('keydown', onKeyDown, { capture: true });
      window.removeEventListener('pointerdown', onPointerDown);
    };
  }, [closeFindPath]);

  return (
    <div className="sv-find-path" ref={panelRef} role="dialog" aria-label="Find a path between two types">
      <Paper elevation={2} padding={16}>
        <div className="sv-find-path__body">
          <div className="sv-find-path__header">
            <Text variant="title-xs" as="h2">Find path between types</Text>
            <IconAction icon="x" label="Close" onClick={closeFindPath} />
          </div>
          <div className="sv-find-path__endpoints">
            <TypeCombobox schema={schema} value={findPath.fromTypeId} onChange={(fromTypeId) => setFindPath({ fromTypeId })} placeholder="Start type" label="Start type" />
            <IconAction
              icon="arrow-up-down"
              label="Swap start and end"
              onClick={() => setFindPath({ fromTypeId: findPath.toTypeId, toTypeId: findPath.fromTypeId })}
            />
            <TypeCombobox schema={schema} value={findPath.toTypeId} onChange={(toTypeId) => setFindPath({ toTypeId })} placeholder="End type" label="End type" />
          </div>
          <div className="sv-find-path__options">
            <Switch
              checked={findPath.options.directed}
              onCheckedChange={(directed) => setFindPath({ options: { ...findPath.options, directed } })}
              label="Follow relation direction"
            />
            <Switch
              checked={findPath.options.includeRefs}
              onCheckedChange={(includeRefs) => setFindPath({ options: { ...findPath.options, includeRefs } })}
              label="Through ref attributes"
            />
          </div>
          <div aria-live="polite" className="sv-find-path__result">
            {result.status === 'incomplete' && (
              <Text variant="content-compact" as="p" className="sv-muted">Pick two types to find the shortest chain of relations between them.</Text>
            )}
            {result.status === 'not-found' && (
              <Alert
                severity="warning"
                title="No path between these types"
                description={findPath.options.includeRefs ? undefined : 'Try going through ref attributes.'}
              />
            )}
            {result.status === 'found' && (
              <>
                <Text variant="content-caption" as="p" className="sv-muted">
                  {result.path.steps.length === 0 ? 'Same type.' : `${result.path.steps.length} ${result.path.steps.length === 1 ? 'hop' : 'hops'}`}
                </Text>
                <PathSteps schema={schema} path={result.path} />
                <Button
                  startIcon={<Icon name="locate-fixed" size={16} />}
                  onClick={() => { showPath(result.path); closeFindPath(); }}
                  disabled={result.path.steps.length === 0}
                >
                  Show on canvas
                </Button>
              </>
            )}
          </div>
        </div>
      </Paper>
    </div>
  );
};
