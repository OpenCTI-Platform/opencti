import React, { useEffect, useMemo, useState } from 'react';
import { Input } from '@filigran/design-system';
import { fetchQuery } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import useVocabularyCategory from '../../../../utils/hooks/useVocabularyCategory';
import { vocabularySearchQuery } from '../../settings/VocabularyQuery';
import { labelsSearchQuery } from '../../settings/LabelsQuery';
import type { VocabularyQuery$data } from '../../settings/__generated__/VocabularyQuery.graphql';
import type { LabelsQuerySearchQuery$data } from '../../settings/__generated__/LabelsQuerySearchQuery.graphql';
import { IrEntityPicker, IrMultiSelect } from './IrFields';
import type { IrPresetValue } from './irPresetDraft';
import type { IrPresetRule } from './irPresetRules';

interface Option {
  value: string;
  label: string;
}

interface FieldProps {
  rule: IrPresetRule;
  value: IrPresetValue;
  onChange: (v: IrPresetValue) => void;
}

const FIELD_STYLE: React.CSSProperties = { minWidth: 240, flex: '1 1 240px' };

const numberBounds = (key: string): { min: number; max?: number; step: number } => {
  if (key === 'cvss') return { min: 0, max: 10, step: 0.1 };
  if (key === 'epss') return { min: 0, max: 1, step: 0.01 };
  return { min: 0, step: 1 };
};

// Vocabulary values of the category the rule's field belongs to. Its own component so that
// only vocabulary rules wait for the vocabulary categories to load.
const VocabularyValueField = ({ rule, value, onChange }: FieldProps) => {
  const { t_i18n } = useFormatter();
  const { fieldToCategory } = useVocabularyCategory();
  const category = rule.vocabularyField ? fieldToCategory(rule.appliesTo[0], rule.vocabularyField) : undefined;
  const [options, setOptions] = useState<Option[]>([]);
  useEffect(() => {
    if (!category) {
      setOptions([]);
      return undefined;
    }
    let active = true;
    fetchQuery(vocabularySearchQuery, { category })
      .toPromise()
      .then((data) => {
        if (!active) return;
        setOptions(((data as VocabularyQuery$data)?.vocabularies?.edges ?? []).map((e) => ({ value: e.node.name, label: e.node.name })));
      });
    return () => {
      active = false;
    };
  }, [category]);
  return (
    <IrMultiSelect
      values={value.terms}
      options={options}
      onChange={(terms) => onChange({ ...value, terms })}
      placeholder={t_i18n('Add…')}
    />
  );
};

const LabelsValueField = ({ value, onChange }: Omit<FieldProps, 'rule'>) => {
  const { t_i18n } = useFormatter();
  const [fetched, setFetched] = useState<Option[]>([]);
  useEffect(() => {
    let active = true;
    fetchQuery(labelsSearchQuery, { search: '', orderBy: 'value', orderMode: 'asc' })
      .toPromise()
      .then((data) => {
        if (!active) return;
        setFetched(((data as LabelsQuerySearchQuery$data)?.labels?.edges ?? []).map((e) => ({ value: e.node.id, label: e.node.value ?? e.node.id })));
      });
    return () => {
      active = false;
    };
  }, []);
  // Already selected labels stay listed even if the fetched page does not contain them.
  const options = useMemo(() => [
    ...fetched,
    ...value.entities.filter((e) => !fetched.some((o) => o.value === e.value)).map((e) => ({ value: e.value, label: e.label })),
  ], [fetched, value.entities]);
  return (
    <IrMultiSelect
      values={value.entities.map((e) => e.value)}
      options={options}
      onChange={(ids) => onChange({
        ...value,
        entities: ids.map((id) => ({ value: id, label: options.find((o) => o.value === id)?.label ?? id, type: 'Label' })),
      })}
      placeholder={t_i18n('Add a label…')}
    />
  );
};

/**
 * The one editable value of a preset rule, shown inline after the rule's sentence.
 * value.entities: picked entities or labels; value.types: "any <Type>" choices or container types;
 * value.terms: vocabulary values, keywords and text; value.number: the number.
 */
export const IrPresetValueField = ({ rule, value, onChange }: FieldProps) => {
  const { t_i18n } = useFormatter();
  const typeOptions: Option[] = (rule.valueTypes ?? []).map((type) => ({ value: type, label: t_i18n(`entity_${type}`) }));
  switch (rule.value) {
    case 'entities':
      return (
        <div style={FIELD_STYLE}>
          <IrEntityPicker
            types={rule.valueTypes}
            value={value.entities}
            onChange={(entities) => onChange({ ...value, entities })}
            placeholder={t_i18n('Search…')}
          />
        </div>
      );
    case 'entitiesOrType':
      return (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, flex: '1 1 480px' }}>
          <div style={FIELD_STYLE}>
            <IrEntityPicker
              types={rule.valueTypes}
              value={value.entities}
              onChange={(entities) => onChange({ ...value, entities })}
              placeholder={t_i18n('Search…')}
            />
          </div>
          <div style={FIELD_STYLE}>
            <IrMultiSelect
              values={value.types}
              options={typeOptions.map((o) => ({ value: o.value, label: `${t_i18n('Any')} ${o.label}` }))}
              onChange={(types) => onChange({ ...value, types })}
              placeholder={t_i18n('Search…')}
            />
          </div>
        </div>
      );
    case 'vocabulary':
      return (
        <div style={FIELD_STYLE}>
          <VocabularyValueField rule={rule} value={value} onChange={onChange} />
        </div>
      );
    case 'labels':
      return (
        <div style={FIELD_STYLE}>
          <LabelsValueField value={value} onChange={onChange} />
        </div>
      );
    case 'keywords':
    case 'text':
      return (
        <div style={FIELD_STYLE}>
          <IrMultiSelect
            values={value.terms}
            options={[]}
            allowCustom
            onChange={(terms) => onChange({ ...value, terms })}
            placeholder={t_i18n('Type and press Enter…')}
          />
        </div>
      );
    case 'number': {
      const { min, max, step } = numberBounds(rule.key);
      return (
        <div style={{ width: 120 }}>
          <Input
            type="number"
            aria-label={rule.sentence}
            min={min}
            max={max}
            step={step}
            value={value.number === null ? '' : String(value.number)}
            onChange={(e) => {
              if (e.target.value === '') {
                onChange({ ...value, number: null });
                return;
              }
              const parsed = Number(e.target.value);
              if (Number.isNaN(parsed)) return;
              const bounded = Math.max(min, max === undefined ? parsed : Math.min(max, parsed));
              onChange({ ...value, number: bounded });
            }}
          />
        </div>
      );
    }
    case 'containerTypes':
      return (
        <div style={FIELD_STYLE}>
          <IrMultiSelect
            values={value.types}
            options={typeOptions}
            onChange={(types) => onChange({ ...value, types })}
            placeholder={t_i18n('Add…')}
          />
        </div>
      );
    default:
      return null;
  }
};

export default IrPresetValueField;
