import { Button, Chip, Icon, Tabs, TabsContent, TabsList, TabsTrigger, Text, Thumbnail } from '@filigran/design-system';
import { type CSSProperties, useMemo, useState } from 'react';
import type { NormalizedSchema, SchemaType } from '../../data/schemaTypes';
import { useSchemaGraphStore } from '../../state/schemaGraphStore';
import { CATEGORY_META, entityFamily, typeColor, typeIcon } from '../../shared/theme/typeAppearance';
import { IconAction } from '../../shared/ui/IconAction';
import { AttributeTable } from './AttributeTable';
import { Counterparts, RelationList } from './RelationList';
import { incomingRows, outgoingRows, usageRows } from './relationRows';
import { TypeLink } from './TypeLink';
import './inspector.css';

const KIND_LABEL: Record<SchemaType['category'], string> = {
  SDO: 'STIX Domain Object',
  SCO: 'STIX Cyber Observable',
  SRO: 'STIX Relationship',
  Meta: 'STIX Meta Object',
  Internal: 'OpenCTI internal type',
  Abstract: 'Abstract root type',
};

type Tab = 'attributes' | 'relations' | 'usage';

const Hierarchy = ({ schema, type }: { schema: NormalizedSchema; type: SchemaType }) => {
  const ancestors = type.ancestorIds.map((id) => schema.types.get(id)).filter((ancestor): ancestor is SchemaType => ancestor !== undefined);
  if (ancestors.length === 0 && type.childIds.length === 0) return null;

  return (
    <div className="sv-hierarchy">
      {ancestors.length > 0 && (
        <nav className="sv-hierarchy__lineage" aria-label="Ancestors">
          {ancestors.map((ancestor) => (
            <span key={ancestor.id} className="sv-hierarchy__step">
              <TypeLink type={ancestor} />
              <Icon name="chevron-right" size={16} className="sv-faint" />
            </span>
          ))}
          <Text variant="content-compact-bold" as="span">{type.label}</Text>
        </nav>
      )}
      {type.childIds.length > 0 && (
        <div className="sv-hierarchy__children">
          <Text variant="content-caption" as="span" className="sv-muted">{type.childIds.length} subtypes</Text>
          <Counterparts schema={schema} ids={type.childIds} />
        </div>
      )}
    </div>
  );
};

const Usage = ({ schema, type }: { schema: NormalizedSchema; type: SchemaType }) => {
  const rows = useMemo(() => usageRows(schema, type), [schema, type]);
  if (rows.length === 0) return <Text variant="content-compact" as="p" className="sv-muted">No entity type declares this relationship directly.</Text>;
  return (
    <ul className="sv-list">
      {rows.map((row) => {
        const source = schema.types.get(row.name);
        return (
          <li key={row.key} className="sv-relation">
            <div className="sv-relation__head">{source && <TypeLink type={source} chip />}</div>
            <div className="sv-relation__counterparts">
              <Text variant="content-caption" as="span" className="sv-relation__direction sv-faint">to</Text>
              <Counterparts schema={schema} ids={row.counterpartIds} />
            </div>
          </li>
        );
      })}
    </ul>
  );
};

export const NodeInspectorPanel = ({ schema, type }: { schema: NormalizedSchema; type: SchemaType }) => {
  const isRelationshipType = type.kind === 'relationship';
  const [preferredTab, setTab] = useState<Tab>(isRelationshipType ? 'usage' : 'attributes');
  const tab = preferredTab === 'usage' && !isRelationshipType ? 'attributes' : preferredTab;
  const selectType = useSchemaGraphStore((state) => state.selectType);
  const focusType = useSchemaGraphStore((state) => state.focusType);
  const toggleExpand = useSchemaGraphStore((state) => state.toggleExpand);
  const togglePinned = useSchemaGraphStore((state) => state.togglePinned);
  const openFindPath = useSchemaGraphStore((state) => state.openFindPath);
  const isExpanded = useSchemaGraphStore((state) => state.expandedTypeIds.includes(type.id));
  const isPinned = useSchemaGraphStore((state) => state.pinnedTypeIds.includes(type.id));

  const relationCount = useMemo(
    () => outgoingRows(schema, type, false).length + incomingRows(schema, type, false)
      .filter((row) => row.viaTypeId === null)
      .reduce((count, row) => count + row.relationIds.length, 0),
    [schema, type],
  );
  const usageCount = useMemo(() => (isRelationshipType ? usageRows(schema, type).length : 0), [schema, type, isRelationshipType]);
  const ownAttributes = type.attributes.filter((attribute) => attribute.declaredBy === type.id).length;
  const family = entityFamily(type);

  return (
    <aside className="sv-inspector" aria-label={`${type.label} details`} style={{ '--sv-type-color': typeColor(type) } as CSSProperties}>
      <header className="sv-inspector__header">
        <Thumbnail className="sv-inspector__thumbnail"><Icon name={typeIcon(type)} size={24} /></Thumbnail>
        <div className="sv-inspector__title">
          <Text variant="title-md" as="h2">{type.label}</Text>
          <div className="sv-inspector__subtitle">
            <Chip label={CATEGORY_META[type.category].label} {...(family ? { entity: family } : { severity: 'neutral' as const })} />
            {type.isAbstract && <Chip label="Abstract" severity="neutral" />}
            <Text variant="content-caption" as="span" className="sv-muted">{KIND_LABEL[type.category]}</Text>
          </div>
        </div>
        <IconAction icon="x" label="Close details" onClick={() => selectType(null)} size="md" />
      </header>

      <div className="sv-inspector__actions">
        <Button size="sm" startIcon={<Icon name="locate-fixed" size={16} />} onClick={() => focusType(type.id)}>Focus</Button>
        {relationCount > 0 && (
          <Button size="sm" priority="secondary" startIcon={<Icon name={isExpanded ? 'minus' : 'network'} size={16} />} onClick={() => toggleExpand(type.id)}>
            {isExpanded ? 'Hide relations' : 'Show relations'}
          </Button>
        )}
        <Button size="sm" priority="secondary" startIcon={<Icon name="route" size={16} />} onClick={() => openFindPath(type.id)}>Find path</Button>
        <IconAction
          icon={isPinned ? 'eye' : 'eye-off'}
          active={isPinned}
          priority="secondary"
          label={isPinned ? 'Remove from the canvas' : 'Add to the canvas'}
          onClick={() => togglePinned(type.id)}
        />
      </div>

      <dl className="sv-inspector__facts">
        <div>
          <Text variant="content-caption" as="dt" className="sv-muted">Attributes</Text>
          <Text variant="title-sm" as="dd">{type.attributes.length}</Text>
          <Text variant="content-caption" as="span" className="sv-faint">{ownAttributes} own</Text>
        </div>
        <div>
          <Text variant="content-caption" as="dt" className="sv-muted">Relations</Text>
          <Text variant="title-sm" as="dd">{relationCount}</Text>
        </div>
        <div>
          <Text variant="content-caption" as="dt" className="sv-muted">Subtypes</Text>
          <Text variant="title-sm" as="dd">{type.childIds.length}</Text>
        </div>
      </dl>

      <Hierarchy key={type.id} schema={schema} type={type} />

      <Tabs value={tab} onValueChange={(value) => setTab(value as Tab)} activationMode="automatic" className="sv-inspector__tabs">
        <TabsList>
          {isRelationshipType && <TabsTrigger value="usage" badge={usageCount} badgeLabel={`${usageCount} type pairs`}>Used between</TabsTrigger>}
          <TabsTrigger value="attributes" badge={type.attributes.length} badgeLabel={`${type.attributes.length} attributes`}>Attributes</TabsTrigger>
          <TabsTrigger value="relations" badge={relationCount} badgeLabel={`${relationCount} relations`}>Relations</TabsTrigger>
        </TabsList>
        {isRelationshipType && <TabsContent value="usage" className="sv-inspector__content"><Usage schema={schema} type={type} /></TabsContent>}
        <TabsContent value="attributes" className="sv-inspector__content"><AttributeTable key={type.id} schema={schema} type={type} /></TabsContent>
        <TabsContent value="relations" className="sv-inspector__content"><RelationList key={type.id} schema={schema} type={type} /></TabsContent>
      </Tabs>
    </aside>
  );
};
