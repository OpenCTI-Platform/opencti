import React, { FunctionComponent, useEffect, useState } from 'react';
import Box from '@mui/material/Box';
import {
  Chip,
  Combobox,
  ComboboxContent,
  ComboboxField,
  ComboboxHelperText,
  ComboboxInput,
  ComboboxLabel,
  Icon,
  IconButton,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Text,
} from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';

export type ComponentObservable = { id: string; entity_type: string; observable_value: string };
export type ComponentRow = ComponentObservable & { type: 'primary' | 'secondary' };

export const FIRST_COMPONENT_PRIMARY = 'The first component must be Primary.';
export const OBSERVABLE_ALREADY_IN_SEQUENCE = 'This observable is already in the sequence.';

// One message per row, or null when the row is valid.
export const componentRowErrors = (rows: readonly ComponentRow[]): (string | null)[] => rows.map((row, index) => {
  if (index === 0 && row.type !== 'primary') return FIRST_COMPONENT_PRIMARY;
  if (rows.findIndex((other) => other.id === row.id) !== index) return OBSERVABLE_ALREADY_IN_SEQUENCE;
  return null;
});

export const canSaveComponents = (rows: readonly ComponentRow[]) => componentRowErrors(rows).every((error) => error === null);

interface ProcedureComponentsFieldProps {
  rows: ComponentRow[];
  onChange: (rows: ComponentRow[]) => void;
  search: (term: string) => Promise<ComponentObservable[]>;
  createText: (value: string) => Promise<ComponentObservable>;
}

const ProcedureComponentsField: FunctionComponent<ProcedureComponentsFieldProps> = ({ rows, onChange, search, createText }) => {
  const { t_i18n } = useFormatter();
  const [term, setTerm] = useState('');
  const [options, setOptions] = useState<ComponentObservable[]>([]);
  const errors = componentRowErrors(rows);

  useEffect(() => {
    let current = true;
    search(term).then((found) => {
      if (current) setOptions(found);
    }).catch(() => undefined);
    return () => {
      current = false;
    };
  }, [term]);

  const move = (from: number, to: number) => {
    const next = [...rows];
    [next[from], next[to]] = [next[to], next[from]];
    onChange(next);
  };
  const add = (observable: ComponentObservable) => {
    setTerm('');
    onChange([...rows, { ...observable, type: 'secondary' }]);
  };

  return (
    <div>
      <Box sx={{ marginBottom: 1 }}>
        <Text variant="content-caption">{t_i18n('Components')}</Text>
      </Box>
      {rows.map((row, index) => (
        <Box key={`${row.id}-${index}`} sx={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 1, marginBottom: 1 }}>
          <Box component="span" sx={{ minWidth: 24, textAlign: 'right' }}>{index}</Box>
          <Box sx={{ flex: 1, minWidth: 0, display: 'flex', alignItems: 'center', gap: 1 }}>
            <Chip label={t_i18n(`entity_${row.entity_type}`)} entity="observations" />
            <Box component="span" sx={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={row.observable_value}>
              {row.observable_value}
            </Box>
          </Box>
          <Select
            value={row.type}
            onValueChange={(type) => onChange(rows.map((r, i) => (i === index ? { ...r, type: type as ComponentRow['type'] } : r)))}
          >
            <SelectTrigger aria-label={`${t_i18n('Type')} ${index}`}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={`${t_i18n('Type')} ${index}`}>
              <SelectItem value="primary">{t_i18n('Primary')}</SelectItem>
              <SelectItem value="secondary">{t_i18n('Secondary')}</SelectItem>
            </SelectContent>
          </Select>
          <IconButton
            icon={<Icon name="arrow-up" size={16} />}
            aria-label={`Move component ${index} up`}
            priority="tertiary"
            size="sm"
            disabled={index === 0}
            onClick={() => move(index, index - 1)}
          />
          <IconButton
            icon={<Icon name="arrow-down" size={16} />}
            aria-label={`Move component ${index} down`}
            priority="tertiary"
            size="sm"
            disabled={index === rows.length - 1}
            onClick={() => move(index, index + 1)}
          />
          <IconButton
            icon={<Icon name="trash-2" size={16} />}
            aria-label={`Remove component ${index}`}
            variant="destructive"
            priority="tertiary"
            size="sm"
            onClick={() => onChange(rows.filter((_, i) => i !== index))}
          />
          {errors[index] && (
            <Box sx={{ flexBasis: '100%', color: 'error.main' }}>{t_i18n(errors[index])}</Box>
          )}
        </Box>
      ))}
      <Combobox<ComponentObservable>
        options={options}
        value={null}
        onValueChange={(picked) => {
          if (picked && !Array.isArray(picked)) add(picked as ComponentObservable);
        }}
        inputValue={term}
        onInputChange={(value) => setTerm(value)}
        getOptionLabel={(option) => `${t_i18n(`entity_${option.entity_type}`)}: ${option.observable_value}`}
        isOptionEqualToValue={(a, b) => a.id === b.id}
        onCreateOption={(value) => {
          createText(value).then(add).catch(() => undefined);
        }}
        createOptionLabel={(value) => `${t_i18n('Create Text observable')} “${value}”`}
      >
        <ComboboxLabel>{t_i18n('Add a component')}</ComboboxLabel>
        <ComboboxField>
          <ComboboxInput />
        </ComboboxField>
        <ComboboxContent listAriaLabel={t_i18n('Add a component')} />
        {rows.length === 0 && <ComboboxHelperText>{t_i18n('No components')}</ComboboxHelperText>}
      </Combobox>
    </div>
  );
};

export default ProcedureComponentsField;
