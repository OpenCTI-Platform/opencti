import { Chip, Icon, type IconName, SearchField, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Switch, Text } from '@filigran/design-system';
import { useMemo, useState } from 'react';
import type { AttributeDef, NormalizedSchema, SchemaType } from '../../data/schemaTypes';
import { IconAction } from '../../shared/ui/IconAction';
import { TypeLink } from './TypeLink';

const typeIcon = (attribute: AttributeDef): IconName => {
  if (attribute.format === 'id') return 'key-round';
  if (attribute.format === 'vocabulary' || attribute.format === 'enum') return 'list';
  switch (attribute.type) {
    case 'date': return 'calendar';
    case 'numeric': return 'chart-column';
    case 'boolean': return 'circle-check';
    case 'object': return 'code-xml';
    default: return 'type';
  }
};

const typeLabel = (attribute: AttributeDef) => {
  const base = attribute.format && attribute.format !== 'short' && attribute.format !== 'standard' ? `${attribute.type}:${attribute.format}` : attribute.type;
  return attribute.multiple ? `${base}[]` : base;
};

const MANDATORY_CHIPS: Partial<Record<AttributeDef['mandatory'], { label: string; severity: 'high' | 'info' | 'neutral' }>> = {
  external: { label: 'Required', severity: 'high' },
  customizable: { label: 'Configurable', severity: 'info' },
  internal: { label: 'Platform', severity: 'neutral' },
};

const AttributeRow = ({ attribute }: { attribute: AttributeDef }) => {
  const mandatory = MANDATORY_CHIPS[attribute.mandatory];
  return (
    <li className="sv-attribute">
      <Icon name={typeIcon(attribute)} size={16} className="sv-attribute__icon" />
      <span className="sv-attribute__text">
        <Text variant="content-code" as="span" className="sv-attribute__name">{attribute.name}</Text>
        <Text variant="content-caption" as="span" className="sv-faint">{typeLabel(attribute)} · {attribute.label}</Text>
      </span>
      <span className="sv-attribute__chips">
        {mandatory && <Chip label={mandatory.label} severity={mandatory.severity} />}
        <Chip label={attribute.isStix ? 'STIX' : 'EXT'} severity={attribute.isStix ? 'info' : 'neutral'} />
      </span>
    </li>
  );
};

type Scope = 'all' | 'own' | 'inherited';

export const AttributeTable = ({ schema, type }: { schema: NormalizedSchema; type: SchemaType }) => {
  const [filter, setFilter] = useState('');
  const [scope, setScope] = useState<Scope>('all');
  const [hidePlatform, setHidePlatform] = useState(false);
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({});

  const groups = useMemo(() => {
    const term = filter.trim().toLowerCase();
    const matching = type.attributes.filter((attribute) => (!term || attribute.name.toLowerCase().includes(term) || attribute.label.toLowerCase().includes(term))
      && (!hidePlatform || attribute.mandatory !== 'internal')
      && (scope === 'all' || (scope === 'own') === (attribute.declaredBy === type.id)));
    // Own attributes first, then nearest ancestor to root.
    const order = [type.id, ...[...type.ancestorIds].reverse()];
    return order
      .map((declaredBy) => ({ declaredBy, attributes: matching.filter((attribute) => attribute.declaredBy === declaredBy).sort((a, b) => a.name.localeCompare(b.name)) }))
      .filter((group) => group.attributes.length > 0);
  }, [type, filter, scope, hidePlatform]);

  const ownCount = type.attributes.filter((attribute) => attribute.declaredBy === type.id).length;
  const searching = filter.trim().length > 0;

  return (
    <div className="sv-inspector__list">
      <div className="sv-inspector__toolbar">
        <SearchField size="sm" fullWidth value={filter} onChange={(event) => setFilter(event.target.value)} onClear={() => setFilter('')} placeholder="Filter attributes" aria-label="Filter attributes" />
        <Select value={scope} onValueChange={(value) => setScope(value as Scope)}>
          <SelectTrigger aria-label="Attribute origin" className="sv-inspector__select">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All</SelectItem>
            <SelectItem value="own">{`Own (${ownCount})`}</SelectItem>
            <SelectItem value="inherited">Inherited</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <Switch checked={hidePlatform} onCheckedChange={setHidePlatform} label="Hide platform-managed attributes" />
      {groups.length === 0 && <Text variant="content-compact" as="p" className="sv-muted">No attribute matches.</Text>}
      {groups.map((group) => {
        const own = group.declaredBy === type.id;
        const open = searching || own || openGroups[group.declaredBy] === true;
        const declaringType = schema.types.get(group.declaredBy);
        return (
          <section key={group.declaredBy} className="sv-group">
            <header className="sv-group__header">
              {!own && !searching && (
                <IconAction
                  icon={open ? 'chevron-down' : 'chevron-right'}
                  label={open ? 'Collapse' : 'Expand'}
                  aria-expanded={open}
                  onClick={() => setOpenGroups({ ...openGroups, [group.declaredBy]: !open })}
                />
              )}
              <Text variant="content-caption" as="span" className="sv-muted">{own ? 'Declared on this type' : 'Inherited from'}</Text>
              {!own && declaringType && <TypeLink type={declaringType} />}
              <Text variant="content-caption" as="span" className="sv-group__count sv-faint">{group.attributes.length}</Text>
            </header>
            {open && <ul className="sv-list">{group.attributes.map((attribute) => <AttributeRow key={attribute.name} attribute={attribute} />)}</ul>}
          </section>
        );
      })}
    </div>
  );
};
