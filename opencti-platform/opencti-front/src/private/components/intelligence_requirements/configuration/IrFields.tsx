import React, { useEffect, useMemo, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import {
  Combobox,
  ComboboxChips,
  ComboboxClear,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from '@filigran/design-system';
import Box from '@mui/material/Box';
import IconButton from '@common/button/IconButton';
import Button from '@common/button/Button';
import { DeleteOutlined } from '@mui/icons-material';
import { fetchQuery } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import type { IrCondition, IrEntityOption } from './irConfigTypes';
import { IR_ATTRIBUTES, IR_ENTITY_TYPES, IR_OPERATOR_LABELS } from './irConstants';
import type { IrFieldsEntitySearchQuery } from './__generated__/IrFieldsEntitySearchQuery.graphql';

// Small controlled fields (no Formik) used by the configuration screen.

interface Option {
  value: string;
  label: string;
}

export const IrSelect = ({ label, value, options, onChange, width }: {
  label?: string;
  value: string;
  options: Option[];
  onChange: (value: string) => void;
  width?: number | string;
}) => (
  <div style={{ width: width ?? '100%' }}>
    <Select value={value} onValueChange={onChange}>
      {label ? <SelectLabel>{label}</SelectLabel> : null}
      <SelectTrigger className="w-full" aria-label={label}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent aria-label={label}>
        {options.map((o) => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}
      </SelectContent>
    </Select>
  </div>
);

export const IrMultiSelect = ({ label, values, options, onChange, allowCustom = false, placeholder }: {
  label?: string;
  values: string[];
  options: Option[];
  onChange: (values: string[]) => void;
  allowCustom?: boolean;
  placeholder?: string;
}) => {
  const selected = useMemo(() => values.map((v) => options.find((o) => o.value === v) ?? { value: v, label: v }), [values, options]);
  return (
    <Combobox<Option>
      options={options}
      value={selected}
      multiple
      closeOnSelect={false}
      onValueChange={(next) => onChange(((next as Option[] | null) ?? []).map((o) => o.value))}
      getOptionLabel={(o) => o.label}
      isOptionEqualToValue={(a, b) => a.value === b.value}
      allowCustomValue={allowCustom}
      createValueFromInput={allowCustom ? (input: string) => ({ value: input.trim(), label: input.trim() }) : undefined}
    >
      {label ? <ComboboxLabel>{label}</ComboboxLabel> : null}
      <ComboboxField>
        <ComboboxChips aria-label={label} />
        <ComboboxInput placeholder={placeholder} />
        <ComboboxControls>
          <ComboboxClear />
          <ComboboxTrigger />
        </ComboboxControls>
      </ComboboxField>
      <ComboboxContent listAriaLabel={label} />
    </Combobox>
  );
};

const entitySearchQuery = graphql`
  query IrFieldsEntitySearchQuery($search: String, $types: [String]) {
    stixCoreObjects(search: $search, types: $types, first: 25) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
        }
      }
    }
  }
`;

/**
 * Search and pick entities of any type (anchors of a list subject group, targets of a path condition).
 */
export const IrEntityPicker = ({ label, value, onChange, types }: {
  label?: string;
  value: IrEntityOption[];
  onChange: (value: IrEntityOption[]) => void;
  types?: string[];
}) => {
  const { t_i18n } = useFormatter();
  const [input, setInput] = useState('');
  const [options, setOptions] = useState<IrEntityOption[]>([]);
  const [loading, setLoading] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => {
    clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      setLoading(true);
      fetchQuery<IrFieldsEntitySearchQuery>(entitySearchQuery, { search: input, types: types && types.length > 0 ? types : null })
        .toPromise()
        .then((data) => {
          setOptions((data?.stixCoreObjects?.edges ?? []).map((e) => ({
            value: e.node.id,
            label: `${e.node.representative.main} (${t_i18n(`entity_${e.node.entity_type}`)})`,
            type: e.node.entity_type,
          })));
        })
        .finally(() => setLoading(false));
    }, 300);
    return () => clearTimeout(timer.current);
  }, [input, (types ?? []).join(',')]);
  return (
    <Combobox<IrEntityOption>
      options={options}
      value={value}
      multiple
      loading={loading}
      closeOnSelect={false}
      inputValue={input}
      onInputChange={(next) => setInput(next)}
      filterOptions={(opts) => opts}
      onValueChange={(next) => onChange((next as IrEntityOption[] | null) ?? [])}
      getOptionLabel={(o) => o.label}
      isOptionEqualToValue={(a, b) => a.value === b.value}
    >
      {label ? <ComboboxLabel>{label}</ComboboxLabel> : null}
      <ComboboxField>
        <ComboboxChips aria-label={label} />
        <ComboboxInput placeholder={t_i18n('Search entities…')} />
        <ComboboxControls>
          <ComboboxClear />
          <ComboboxTrigger />
        </ComboboxControls>
      </ComboboxField>
      <ComboboxContent listAriaLabel={label} />
    </Combobox>
  );
};

/**
 * Simplified filter builder: a list of OpenCTI filters on the entity (combined with AND).
 */
export const IrConditionsEditor = ({ conditions, onChange, addLabel }: {
  conditions: IrCondition[];
  onChange: (conditions: IrCondition[]) => void;
  addLabel?: string;
}) => {
  const { t_i18n } = useFormatter();
  const update = (index: number, patch: Partial<IrCondition>) => onChange(conditions.map((c, i) => (i === index ? { ...c, ...patch } : c)));
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
      {conditions.map((condition, index) => {
        const definition = IR_ATTRIBUTES.find((a) => a.key === condition.key) ?? IR_ATTRIBUTES[0];
        let valueField;
        if (definition.kind === 'number') {
          valueField = <Input aria-label={t_i18n('Value')} type="number" value={condition.value} onChange={(e) => update(index, { value: e.target.value })} />;
        } else {
          const values = definition.kind === 'type' ? IR_ENTITY_TYPES : (definition.values ?? []);
          valueField = <IrSelect value={condition.value} options={values.map((v) => ({ value: v, label: definition.kind === 'type' ? t_i18n(`entity_${v}`) : v }))} onChange={(v) => update(index, { value: v })} />;
        }
        return (
          <Box key={index} sx={{ display: 'grid', gridTemplateColumns: '1.3fr 0.6fr 1fr 32px', gap: 1, alignItems: 'center' }}>
            <IrSelect
              value={condition.key}
              options={IR_ATTRIBUTES.map((a) => ({ value: a.key, label: t_i18n(a.label) }))}
              onChange={(key) => {
                const next = IR_ATTRIBUTES.find((a) => a.key === key) ?? IR_ATTRIBUTES[0];
                update(index, { key, operator: next.operators[0], value: next.values?.[0] ?? (next.kind === 'type' ? IR_ENTITY_TYPES[0] : '') });
              }}
            />
            <IrSelect
              value={condition.operator}
              options={definition.operators.map((o) => ({ value: o, label: IR_OPERATOR_LABELS[o] ?? o }))}
              onChange={(operator) => update(index, { operator })}
            />
            {valueField}
            <IconButton aria-label={t_i18n('Delete')} onClick={() => onChange(conditions.filter((_, i) => i !== index))}>
              <DeleteOutlined fontSize="small" />
            </IconButton>
          </Box>
        );
      })}
      <div>
        <Button variant="tertiary" size="small" onClick={() => onChange([...conditions, { key: 'x_opencti_cisa_kev', operator: 'eq', value: 'true' }])}>
          {addLabel ?? t_i18n('Add condition')}
        </Button>
      </div>
    </Box>
  );
};
