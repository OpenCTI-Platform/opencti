import React from 'react';
import { Chip, Text } from '@filigran/design-system';
import { Box } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import type { TimeMachineValueData } from './timeMachineUtils';

interface TimeMachineValuesProps {
  values: ReadonlyArray<TimeMachineValueData>;
  type: string;
  multiple: boolean;
}

const MAX_TEXT_LENGTH = 600;

/**
 * Display the values of an attribute as reconstructed by the time machine.
 * Restricted references never expose their name, deleted references are shown as tombstones.
 */
const TimeMachineValues = ({ values, type, multiple }: TimeMachineValuesProps) => {
  const { t_i18n, fldt } = useFormatter();
  if (values.length === 0) {
    return <Text variant="content-compact" style={{ color: 'var(--text-default-secondary)' }}>-</Text>;
  }
  const labelOf = (value: TimeMachineValueData) => {
    if (value.restricted) return t_i18n('Restricted');
    if (value.deleted) return `${value.display === 'Deleted' ? t_i18n('Deleted') : value.display} (${t_i18n('deleted')})`;
    if (type === 'date') return fldt(value.display);
    if (type === 'boolean') return value.display === 'true' ? t_i18n('Yes') : t_i18n('No');
    return value.display;
  };
  if (multiple || type === 'ref') {
    return (
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
        {values.map((value, index) => (
          <Chip
            key={`${value.raw}-${index}`}
            label={labelOf(value)}
            severity={value.deleted || value.restricted ? 'neutral' : 'info'}
          />
        ))}
      </Box>
    );
  }
  const text = labelOf(values[0]);
  return (
    <Text variant="content-compact" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
      {text.length > MAX_TEXT_LENGTH ? `${text.substring(0, MAX_TEXT_LENGTH)}...` : text}
    </Text>
  );
};

export default TimeMachineValues;
