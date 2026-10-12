import React from 'react';
import { Chip, Text } from '@filigran/design-system';
import { Box } from '@mui/material';
import { AddCircleOutline, RemoveCircleOutline } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import type { TimeMachineValueData } from './timeMachineUtils';

export type TimeMachineValueTone = 'added' | 'removed';

interface TimeMachineValuesProps {
  values: ReadonlyArray<TimeMachineValueData>;
  type: string;
  multiple: boolean;
  // Tone of the values that changed during the period; the other values stay neutral
  tone?: TimeMachineValueTone;
  // Raw values that changed, for multiple attributes; every value when not set
  changed?: ReadonlyArray<string>;
}

const MAX_TEXT_LENGTH = 600;

const TONE_COLORS: Record<TimeMachineValueTone, string> = {
  added: 'var(--color-feedback-success-primary)',
  removed: 'var(--color-feedback-error-primary)',
};

// Success and error tones of the design-system chips
const CHIP_SEVERITIES = { added: 'low', removed: 'high' } as const;

const ToneIcon = ({ tone }: { tone: TimeMachineValueTone }) => {
  const { t_i18n } = useFormatter();
  const Icon = tone === 'added' ? AddCircleOutline : RemoveCircleOutline;
  return (
    <Icon
      fontSize="inherit"
      titleAccess={tone === 'added' ? t_i18n('Added') : t_i18n('Removed')}
      style={{ color: tone === 'added' ? 'var(--icon-success)' : 'var(--icon-error)', flexShrink: 0, marginTop: 3 }}
    />
  );
};

/**
 * Display the values of an attribute as reconstructed by the time machine.
 * Restricted references never expose their name, deleted references are shown as tombstones.
 * Values that changed during the period carry their tone and an icon (colour is never the only signal);
 * removed values are struck through.
 */
const TimeMachineValues = ({ values, type, multiple, tone, changed }: TimeMachineValuesProps) => {
  const { t_i18n, fldt } = useFormatter();
  if (values.length === 0) {
    return <Text variant="content-compact" style={{ color: 'var(--text-default-secondary)' }}>{t_i18n('Not set')}</Text>;
  }
  const labelOf = (value: TimeMachineValueData) => {
    if (value.restricted) return t_i18n('Restricted');
    if (value.deleted) return value.display === 'Deleted' ? t_i18n('Deleted') : t_i18n('{value} (deleted)', { values: { value: value.display } });
    if (type === 'date') return fldt(value.display);
    if (type === 'boolean') return value.display === 'true' ? t_i18n('Yes') : t_i18n('No');
    return value.display;
  };
  const toneOf = (value: TimeMachineValueData) => (tone && (!changed || changed.includes(value.raw)) ? tone : undefined);
  if (multiple || type === 'ref') {
    return (
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
        {values.map((value, index) => {
          const valueTone = toneOf(value);
          return (
            <Chip
              key={`${value.raw}-${index}`}
              label={labelOf(value)}
              severity={valueTone ? CHIP_SEVERITIES[valueTone] : 'neutral'}
              startIcon={valueTone ? <ToneIcon tone={valueTone} /> : undefined}
              style={valueTone === 'removed' ? { textDecoration: 'line-through' } : undefined}
            />
          );
        })}
      </Box>
    );
  }
  const text = labelOf(values[0]);
  const valueTone = toneOf(values[0]);
  return (
    <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 0.5 }}>
      {valueTone && <ToneIcon tone={valueTone} />}
      <Text
        variant="content-compact"
        style={{
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
          ...(valueTone ? { color: TONE_COLORS[valueTone] } : {}),
          ...(valueTone === 'removed' ? { textDecoration: 'line-through' } : {}),
        }}
      >
        {text.length > MAX_TEXT_LENGTH ? `${text.substring(0, MAX_TEXT_LENGTH)}...` : text}
      </Text>
    </Box>
  );
};

export default TimeMachineValues;
