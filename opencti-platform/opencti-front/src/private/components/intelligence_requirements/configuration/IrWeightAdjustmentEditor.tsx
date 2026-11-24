import React, { Suspense } from 'react';
import { Icon, Input, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Spinner, Switch, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import useSchema from '../../../../utils/hooks/useSchema';
import IrFilterBuilder from './IrFilterBuilder';
import { IrEntityPicker } from './IrFields';
import {
  choose,
  firstHopBothWays,
  hopOptions,
  hopValue,
  intermediateTypes,
  inverseKey,
  isAdjustmentComplete,
  isSymmetric,
  secondHopOptions,
  verbKey,
  type IrAdjustment,
  type IrHopOption,
  type IrRelationMapping,
} from './irAdjustment';

type Translate = (text: string, values?: { values: Record<string, unknown> }) => string;

const startsWithVowel = (text: string) => /^[aeiou]/i.test(text);

const OPERATORS: Record<string, string> = {
  eq: '=', not_eq: '≠', gt: '>', gte: '≥', lt: '<', lte: '≤', search: 'contains', contains: 'contains', not_contains: 'does not contain',
  starts_with: 'starts with', ends_with: 'ends with', nil: 'is empty', not_nil: 'is not empty',
};
type SummaryFilterGroup = { mode?: string; filters?: { key: string | string[]; operator?: string; values?: unknown[] }[]; filterGroups?: SummaryFilterGroup[] };

// "CISA KEV = true": a filter group as it reads, with the platform's labels for its keys
export const useFiltersSummary = () => {
  const { t_i18n } = useFormatter();
  const { schema } = useSchema();
  const labelOf = (key: string) => {
    for (const definitions of schema.filterKeysSchema.values()) {
      const definition = definitions.get(key);
      if (definition) return t_i18n(definition.label);
    }
    return key;
  };
  const read = (group: SummaryFilterGroup): string => {
    const parts = [
      ...(group.filters ?? []).map((f) => {
        const key = Array.isArray(f.key) ? f.key[0] : f.key;
        const values = (f.values ?? []).map((v) => (typeof v === 'string' && /^[0-9a-f-]{36}$/.test(v) ? null : String(v)));
        const shown = values.includes(null) ? t_i18n('{count} values', { values: { count: values.length } }) : values.join(', ');
        return `${labelOf(key)} ${t_i18n(OPERATORS[f.operator ?? 'eq'] ?? f.operator ?? '=')}${shown ? ` ${shown}` : ''}`;
      }),
      ...(group.filterGroups ?? []).map((g) => `(${read(g)})`),
    ];
    return parts.join(` ${t_i18n(group.mode === 'or' ? 'or' : 'and')} `);
  };
  return (filters: string | null) => {
    if (!filters) return '';
    try {
      return read(JSON.parse(filters) as SummaryFilterGroup);
    } catch {
      return '';
    }
  };
};

// The words of an adjustment: its subject, its condition and the sentence it reads back as
export const adjustmentWords = (a: IrAdjustment, flaggedTypes: string[], weighting: number, t: Translate, describeFilters?: (filters: string | null) => string) => {
  const typeLabel = (type: string) => t(`entity_${type}`).toLowerCase();
  const subject = (() => {
    if (a.appliesTo) return typeLabel(a.appliesTo);
    return flaggedTypes.length === 1 ? typeLabel(flaggedTypes[0]) : t('flagged entity');
  })();
  const points = `${a.points >= 0 ? '+' : ''}${a.points}`;
  const names = a.ends.map((e) => e.label);
  const targets = names.length <= 1 ? (names[0] ?? '') : `${names.slice(0, -1).join(', ')} ${t('or')} ${names[names.length - 1]}`;
  const first = a.rel1 && a.dir1 ? t(verbKey(a.rel1, a.dir1)) : '';
  // a direct link always counts both directions, so it reads as the relationship chosen; through an entity,
  // "either direction" reads as both: "uses or is used by"
  const firstText = a.rel1 && a.dir1 && a.hops === 'two' && firstHopBothWays(a) && !isSymmetric(a.rel1)
    ? t('{relationship} or {inverse}', { values: { relationship: first, inverse: t(inverseKey(a.rel1, a.dir1)) } })
    : first;
  let condition = '';
  const properties = a.kind === 'property' && describeFilters ? describeFilters(a.filters) : '';
  if (a.kind === 'property') condition = properties ? t('that has {properties}', { values: { properties } }) : t('that has these properties');
  else if (a.hops === 'direct') condition = t('that {relationship} {targets}', { values: { relationship: firstText, targets } });
  else if (a.hops === 'two' && a.inter && a.rel2) {
    const inter = typeLabel(a.inter);
    const type = startsWithVowel(inter) ? t('an {type}', { values: { type: inter } }) : t('a {type}', { values: { type: inter } });
    condition = t('that {relationship} {type} that {relationship2} {targets}', {
      values: { relationship: firstText, type, relationship2: t(verbKey(a.rel2, 'outgoing')), targets },
    });
  }
  return {
    subject,
    name: `${subject.charAt(0).toUpperCase()}${subject.slice(1)} ${condition}`,
    sentence: t('Adjusts the weighting by {points} for each {subject} {condition}.', { values: { points, subject, condition } }),
    weighting: t('From {from} to {to} for these entities.', { values: { from: weighting, to: weighting + a.points } }),
  };
};

// A dropdown of the adjustment sentence: shows its placeholder until a choice is made
const Choice = ({ label, value, placeholder, options, onChange, width }: {
  label: string;
  value: string | null;
  placeholder: string;
  options: { value: string; label: string }[];
  onChange: (value: string) => void;
  width?: number;
}) => (
  <div style={{ width: width ?? '100%', maxWidth: width ? undefined : 420, flex: width ? 'none' : undefined }}>
    <Select value={value ?? ''} onValueChange={onChange}>
      <SelectTrigger className="w-full" aria-label={label}>
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent position="popper" side="bottom" align="start" sideOffset={4} aria-label={label}>
        {options.map((o) => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}
      </SelectContent>
    </Select>
  </div>
);

const Row = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <>
    <Text as="span" variant="content-compact"><Box component="span" sx={{ color: 'text.secondary' }}>{label}</Box></Text>
    <Box sx={{ minWidth: 0 }}>{children}</Box>
  </>
);

type StepState = 'done' | 'current' | 'todo';

// The path as it is built: the step the form asks for now is highlighted, the steps still to come are dashed
const PathPreview = ({ items, direct }: { items: { kind: 'node' | 'edge'; text: string; caption?: string; state: StepState; both?: boolean }[]; direct: boolean }) => {
  const { t_i18n } = useFormatter();
  const border = (state: StepState) => {
    if (state === 'current') return { border: '2px solid', borderColor: 'primary.main', bgcolor: 'action.selected' };
    if (state === 'todo') return { border: '1px dashed', borderColor: 'divider', color: 'text.disabled' };
    return { border: '1px solid', borderColor: 'divider' };
  };
  return (
    <Box sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 2 }}>
      <Text as="div" variant="content-caption"><Box component="span" sx={{ color: 'text.secondary' }}>{t_i18n('Path')}</Box></Text>
      <Box sx={{ display: 'grid', gridTemplateColumns: direct ? '3fr 2fr 3fr' : '3fr 2fr 3fr 2fr 3fr', columnGap: 1, alignItems: 'end', mt: 1.5 }}>
        {items.map((item, index) => (item.kind === 'node' ? (

          <Box key={index} sx={{ minWidth: 0, display: 'flex', flexDirection: 'column', gap: 0.75 }}>
            <Text as="span" variant="content-caption"><Box component="span" sx={{ color: 'text.secondary' }}>{item.caption}</Box></Text>
            <Box sx={{ ...border(item.state), borderRadius: 1, px: 1.5, py: 0.75, textAlign: 'center', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              <Text as="span" variant="content-compact">{item.text}</Text>
            </Box>
          </Box>
        ) : (

          <Box key={index} sx={{ minWidth: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 0.5, pb: 0.5 }}>
            <Box sx={{ ...border(item.state), borderRadius: 1, px: 1, py: 0.25, maxWidth: '100%', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              <Text as="span" variant="content-caption">{item.text}</Text>
            </Box>
            <Box sx={{ color: item.state === 'current' ? 'primary.main' : 'text.secondary', display: 'flex' }}>
              <Icon name={item.both ? 'arrow-right-left' : 'arrow-right'} size={16} />
            </Box>
          </Box>
        )))}
      </Box>
    </Box>
  );
};

interface IrWeightAdjustmentEditorProps {
  adjustment: IrAdjustment;
  flaggedTypes: string[]; // the types the rule brings in
  weighting: number; // the weighting of the rule, without adjustment
  error?: string | null;
  onChange: (adjustment: IrAdjustment) => void;
  onSave: () => void;
  onCancel: () => void;
}

/**
 * Adjust the weighting of the entities a rule brings in: one choice at a time, each offering only what can follow the
 * one before it. Linked: directly, or through one entity in between (two hops at most).
 */
const IrWeightAdjustmentEditor = ({ adjustment: a, flaggedTypes, weighting, error, onChange, onSave, onCancel }: IrWeightAdjustmentEditorProps) => {
  const { t_i18n } = useFormatter();
  const { schema } = useSchema();
  const allTypes = [...schema.sdos, ...schema.scos].map((type) => type.id);
  const mapping: IrRelationMapping = (from, to) => schema.schemaRelationsTypesMapping.get(`${from}_${to}`) ?? [];
  const typeLabel = (type: string) => t_i18n(`entity_${type}`);
  const describeFilters = useFiltersSummary();
  const words = adjustmentWords(a, flaggedTypes, weighting, t_i18n, describeFilters);
  const severalTypes = flaggedTypes.length > 1;
  const sources = a.appliesTo ? [a.appliesTo] : flaggedTypes;
  const two = a.hops === 'two';

  // first relationship: through an entity, only those leading to a type with a relationship of its own
  const firstOptions = hopOptions(sources, allTypes, mapping).filter((o) => !two || intermediateTypes(o, allTypes, mapping).length > 0);
  const first: IrHopOption | undefined = a.rel1 && a.dir1
    ? (firstOptions.find((o) => o.value === hopValue(a.rel1 as string, a.dir1 as IrHopOption['dir'])) ?? firstOptions.find((o) => o.rel === a.rel1))
    : undefined;
  const interOptions = intermediateTypes(first, allTypes, mapping);
  const secondOptions = a.inter ? secondHopOptions(a.inter, allTypes, mapping) : [];
  const second = secondOptions.find((o) => o.rel === a.rel2);
  const endTypes = (two ? second?.endTypes : first?.endTypes) ?? [];
  const pathReady = two ? !!(first && a.inter && second) : !!first;
  const complete = isAdjustmentComplete(a);

  let current = 'end';
  if (!a.hops || !first) current = 'first';
  else if (two && !a.inter) current = 'inter';
  else if (two && !second) current = 'second';
  else if (a.ends.length > 0) current = 'none';
  const stateOf = (step: string, chosen: boolean): StepState => {
    if (step === current) return 'current';
    return chosen ? 'done' : 'todo';
  };
  const endText = a.ends.length > 0 ? `${a.ends[0].label}${a.ends.length > 1 ? ` +${a.ends.length - 1}` : ''}` : '?';
  const preview: { kind: 'node' | 'edge'; text: string; caption?: string; state: StepState; both?: boolean }[] = [
    { kind: 'node', text: words.subject.charAt(0).toUpperCase() + words.subject.slice(1), caption: severalTypes && !a.appliesTo ? t_i18n('Any flagged type') : t_i18n('Each flagged entity'), state: 'done' },
    { kind: 'edge', text: first ? t_i18n(verbKey(first.rel, first.dir)) : '?', state: stateOf('first', !!first), both: !!first && firstHopBothWays(a) },
  ];
  if (a.hops !== 'direct') {
    preview.push({ kind: 'node', text: a.inter ? typeLabel(a.inter) : '?', caption: t_i18n('Through'), state: stateOf('inter', !!a.inter) });
    preview.push({ kind: 'edge', text: second ? t_i18n(verbKey(second.rel, 'outgoing')) : '?', state: stateOf('second', !!second) });
  }
  preview.push({ kind: 'node', text: endText, caption: t_i18n('Ending at'), state: stateOf('end', a.ends.length > 0) });

  // The picker labels an entity "<name> (<type>)": the adjustment keeps the plain name, used in its sentence
  const plainEntities = (entities: IrAdjustment['ends']) => entities.map((e) => {
    const suffix = ` (${typeLabel(e.type)})`;
    return e.label.endsWith(suffix) ? { ...e, label: e.label.slice(0, -suffix.length) } : e;
  });

  return (
    <Box sx={{ mt: 2, border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 2.5, display: 'flex', flexDirection: 'column', gap: 2.5 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'nowrap', whiteSpace: 'nowrap' }}>
        <Text as="span" variant="content-compact-bold">{t_i18n('Adjust weighting by')}</Text>
        <Box sx={{ width: 72, flex: 'none' }}>
          <Input aria-label={t_i18n('Weighting adjustment')} type="number" value={String(a.points)} onChange={(e) => onChange({ ...a, points: Number.parseInt(e.target.value || '0', 10) || 0 })} />
        </Box>
        <Text as="span" variant="content-compact">{t_i18n('when the')}</Text>
        {severalTypes ? (
          <Choice
            label={t_i18n('Applies to')}
            value={a.appliesTo ?? '__any__'}
            placeholder=""
            width={210}
            options={[{ value: '__any__', label: t_i18n('flagged entity (any type)') }, ...flaggedTypes.map((type) => ({ value: type, label: typeLabel(type).toLowerCase() }))]}
            onChange={(v) => onChange(choose(a, 'appliesTo', { appliesTo: v === '__any__' ? null : v }))}
          />
        ) : <Text as="span" variant="content-compact">{words.subject}</Text>}
        <Choice
          label={t_i18n('Condition')}
          value={a.kind}
          placeholder={t_i18n('Choose a condition…')}
          width={190}
          options={[{ value: 'property', label: t_i18n('has a property…') }, { value: 'linked', label: t_i18n('is linked to…') }]}
          onChange={(v) => onChange(choose(a, 'kind', { kind: v as IrAdjustment['kind'] }))}
        />
      </Box>

      {a.kind === 'property' && (
        <Suspense fallback={<Spinner size="sm" />}>
          <IrFilterBuilder value={a.filters} onChange={(filters) => onChange({ ...a, filters })} />
        </Suspense>
      )}

      {a.kind === 'linked' && (
        <>
          <PathPreview items={preview} direct={a.hops === 'direct'} />
          <Box sx={{ display: 'grid', gridTemplateColumns: '120px minmax(0, 1fr)', columnGap: 2, rowGap: 1.75, alignItems: 'center' }}>
            <Row label={t_i18n('Linked')}>
              <Choice
                label={t_i18n('Linked')}
                value={a.hops}
                placeholder={t_i18n('Choose…')}
                options={[{ value: 'direct', label: t_i18n('directly') }, { value: 'two', label: t_i18n('through another entity') }]}
                onChange={(v) => onChange(choose(a, 'hops', { hops: v as IrAdjustment['hops'] }))}
              />
            </Row>
            {a.hops && (
              <Row label={words.subject.charAt(0).toUpperCase() + words.subject.slice(1)}>
                <Choice
                  label={t_i18n('Relationship')}
                  value={first?.value ?? null}
                  placeholder={t_i18n('Choose a relationship…')}
                  options={firstOptions.map((o) => ({ value: o.value, label: t_i18n(verbKey(o.rel, o.dir)) }))}
                  onChange={(v) => {
                    const option = firstOptions.find((o) => o.value === v);
                    if (option) onChange(choose(a, 'first', { rel1: option.rel, dir1: option.dir }));
                  }}
                />
              </Row>
            )}
            {first && !isSymmetric(first.rel) && (
              <>
                <span />
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                  <Switch
                    label={t_i18n('Either direction')}
                    checked={firstHopBothWays(a)}
                    disabled={a.hops === 'direct'}
                    onCheckedChange={(checked) => onChange({ ...a, bi1: checked })}
                  />
                  <Text as="span" variant="content-caption">
                    <Box component="span" sx={{ color: 'text.secondary' }}>
                      {a.hops === 'direct'
                        ? t_i18n('A direct link counts the relationship in either direction.')
                        : t_i18n('Also counts "{inverse}": the relationship pointing the other way.', { values: { inverse: t_i18n(inverseKey(first.rel, first.dir)) } })}
                    </Box>
                  </Text>
                </Box>
              </>
            )}
            {two && first && (
              <Row label={t_i18n('a / an')}>
                <Choice
                  label={t_i18n('Type of the entity in between')}
                  value={a.inter}
                  placeholder={t_i18n('Choose an entity type…')}
                  options={interOptions.map((type) => ({ value: type, label: typeLabel(type).toLowerCase() }))}
                  onChange={(v) => onChange(choose(a, 'inter', { inter: v }))}
                />
              </Row>
            )}
            {two && a.inter && (
              <Row label={t_i18n('that')}>
                <Choice
                  label={t_i18n('Relationship')}
                  value={second?.rel ?? null}
                  placeholder={t_i18n('Choose a relationship…')}
                  options={secondOptions.map((o) => ({ value: o.rel, label: t_i18n(verbKey(o.rel, 'outgoing')) }))}
                  onChange={(v) => onChange(choose(a, 'rel2', { rel2: v }))}
                />
              </Row>
            )}
            {pathReady && (
              <Row label={t_i18n('Ending at')}>
                <Box sx={{ maxWidth: 560 }}>
                  <IrEntityPicker
                    value={a.ends}
                    types={endTypes}
                    placeholder={t_i18n('Search entities…')}
                    onChange={(ends) => onChange({ ...a, ends: plainEntities(ends) })}
                  />
                </Box>
              </Row>
            )}
          </Box>
        </>
      )}

      {complete && (
        <Box sx={{ bgcolor: 'action.hover', borderRadius: 1, px: 2, py: 1.5 }}>
          <Text as="div" variant="content-compact-bold">{words.sentence}</Text>
          <Text as="div" variant="content-caption"><Box component="span" sx={{ color: 'text.secondary' }}>{words.weighting}</Box></Text>
        </Box>
      )}
      {error && (
        <Text as="p" variant="content-caption"><Box component="span" sx={{ color: 'error.main' }}>{error}</Box></Text>
      )}
      <Box sx={{ display: 'flex', gap: 1 }}>
        <Button size="small" disabled={!complete} onClick={onSave}>{t_i18n('Save weighting')}</Button>
        <Button variant="secondary" size="small" onClick={onCancel}>{t_i18n('Cancel')}</Button>
      </Box>
    </Box>
  );
};

export default IrWeightAdjustmentEditor;
