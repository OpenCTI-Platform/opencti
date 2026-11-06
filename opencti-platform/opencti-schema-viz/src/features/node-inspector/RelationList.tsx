import { Chip, Icon, SearchField, Switch, Text } from '@filigran/design-system';
import { useMemo, useState } from 'react';
import type { NormalizedSchema, SchemaType, StixStatus } from '../../data/schemaTypes';
import { useSchemaGraphStore } from '../../state/schemaGraphStore';
import { IconAction } from '../../shared/ui/IconAction';
import { revealKey } from '../schema-graph/graphIds';
import { incomingRows, outgoingRows, type RelationRow } from './relationRows';
import { TypeLink } from './TypeLink';

const MAX_CHIPS = 8;

const STIX_CHIPS: Record<StixStatus, { label: string; severity: 'info' | 'medium' | 'neutral' }> = {
  builtin: { label: 'STIX', severity: 'info' },
  extended: { label: 'EXT', severity: 'medium' },
  new: { label: 'OpenCTI', severity: 'neutral' },
};

export const Counterparts = ({ schema, ids }: { schema: NormalizedSchema; ids: string[] }) => {
  const [all, setAll] = useState(false);
  const shown = all ? ids : ids.slice(0, MAX_CHIPS);
  return (
    <div className="sv-chips">
      {shown.map((id) => {
        const type = schema.types.get(id);
        return type ? <TypeLink key={id} type={type} chip /> : null;
      })}
      {ids.length > shown.length && (
        <Chip label={`+${ids.length - shown.length} more`} severity="neutral" onClick={() => setAll(true)} />
      )}
    </div>
  );
};

interface RelationSectionProps {
  schema: NormalizedSchema;
  type: SchemaType;
  title: string;
  direction: 'out' | 'in';
  rows: RelationRow[];
}

const RelationSection = ({ schema, type, title, direction, rows }: RelationSectionProps) => {
  const revealed = useSchemaGraphStore((state) => state.revealedRelations);
  const expanded = useSchemaGraphStore((state) => state.expandedTypeIds.includes(type.id));
  const toggleReveal = useSchemaGraphStore((state) => state.toggleReveal);

  return (
    <section className="sv-group">
      <header className="sv-group__header">
        <Icon name={direction === 'out' ? 'arrow-right' : 'arrow-left'} size={16} className="sv-muted" />
        <Text variant="content-compact-bold" as="h3">{title}</Text>
        <Text variant="content-caption" as="span" className="sv-group__count sv-faint">{rows.length}</Text>
      </header>
      {rows.length === 0 && <Text variant="content-compact" as="p" className="sv-muted">None.</Text>}
      <ul className="sv-list">
        {rows.map((row) => {
          const keys = row.relationIds.map((relationId) => revealKey(direction, type.id, relationId));
          const onCanvas = expanded || keys.every((key) => revealed.includes(key));
          const via = row.viaTypeId ? schema.types.get(row.viaTypeId) : undefined;
          return (
            <li key={row.key} className="sv-relation">
              <div className="sv-relation__head">
                <Text variant="content-code" as="span">{row.name}</Text>
                {row.kind === 'ref' && <Chip label="Ref" severity="low" />}
                {row.stixStatus && <Chip label={STIX_CHIPS[row.stixStatus].label} severity={STIX_CHIPS[row.stixStatus].severity} />}
                {via && <Text variant="content-caption" as="span" className="sv-muted">via <TypeLink type={via} /></Text>}
                {!via && (
                  <IconAction
                    icon={onCanvas ? 'eye' : 'eye-off'}
                    active={onCanvas}
                    disabled={expanded}
                    label={expanded ? 'Shown because all relations are expanded' : onCanvas ? `Hide ${row.name} from the canvas` : `Show ${row.name} on the canvas`}
                    onClick={() => keys.forEach((key) => {
                      if (onCanvas === revealed.includes(key)) toggleReveal(key, type.id);
                    })}
                    className="sv-relation__reveal"
                  />
                )}
              </div>
              <div className="sv-relation__counterparts">
                <Text variant="content-caption" as="span" className="sv-relation__direction sv-faint">{direction === 'out' ? 'to' : 'from'}</Text>
                <Counterparts schema={schema} ids={row.counterpartIds} />
              </div>
            </li>
          );
        })}
      </ul>
    </section>
  );
};

export const RelationList = ({ schema, type }: { schema: NormalizedSchema; type: SchemaType }) => {
  const storeIncludeRefs = useSchemaGraphStore((state) => state.includeRefs);
  const [includeRefs, setIncludeRefs] = useState(storeIncludeRefs);
  const [filter, setFilter] = useState('');

  const { outgoing, incoming } = useMemo(() => {
    const term = filter.trim().toLowerCase();
    const matches = (row: RelationRow) => !term || row.name.toLowerCase().includes(term)
      || row.counterpartIds.some((id) => (schema.types.get(id)?.label ?? id).toLowerCase().includes(term));
    return {
      outgoing: outgoingRows(schema, type, includeRefs).filter(matches),
      incoming: incomingRows(schema, type, includeRefs).filter(matches),
    };
  }, [schema, type, includeRefs, filter]);

  return (
    <div className="sv-inspector__list">
      <SearchField size="sm" fullWidth value={filter} onChange={(event) => setFilter(event.target.value)} onClear={() => setFilter('')} placeholder="Filter by relation or type" aria-label="Filter relations" />
      <Switch checked={includeRefs} onCheckedChange={setIncludeRefs} label="Include ref attributes (createdBy, objectMarking…)" />
      <RelationSection schema={schema} type={type} title="Outgoing" direction="out" rows={outgoing} />
      <RelationSection schema={schema} type={type} title="Incoming" direction="in" rows={incoming} />
    </div>
  );
};
