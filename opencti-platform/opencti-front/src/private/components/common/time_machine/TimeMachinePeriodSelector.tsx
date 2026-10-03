import React, { useState } from 'react';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@filigran/design-system';
import { Box } from '@mui/material';
import DateTimePicker from '../../../../components/common/input/DateTimePicker';
import { useFormatter } from '../../../../components/i18n';
import { DateRange, presetLabel, presetRange, TIME_MACHINE_PRESETS, TimeMachinePreset } from './timeMachineUtils';

const CUSTOM_PERIOD = 'custom';

interface TimeMachinePeriodSelectorProps {
  value: DateRange;
  onChange: (range: DateRange) => void;
  initialPreset?: string;
  // Extra preset relative to the user, for instance the date of the last visit
  extraPresets?: Array<{ key: string; label: string; range: DateRange }>;
}

const TimeMachinePeriodSelector = ({ value, onChange, initialPreset = CUSTOM_PERIOD, extraPresets = [] }: TimeMachinePeriodSelectorProps) => {
  const { t_i18n } = useFormatter();
  const [presetKey, setPresetKey] = useState(initialPreset);
  const handlePreset = (key: string) => {
    setPresetKey(key);
    if (key === CUSTOM_PERIOD) return;
    const extra = extraPresets.find((preset) => preset.key === key);
    onChange(extra ? extra.range : presetRange(key as TimeMachinePreset));
  };
  const handleDate = (field: keyof DateRange, date: Date | null) => {
    if (date && !Number.isNaN(date.getTime())) {
      setPresetKey(CUSTOM_PERIOD);
      onChange({ ...value, [field]: date.toISOString() });
    }
  };
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }} data-testid="time-machine-period">
      <Select value={presetKey} onValueChange={handlePreset}>
        <SelectTrigger aria-label={t_i18n('Period')}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent aria-label={t_i18n('Period')}>
          <SelectItem value={CUSTOM_PERIOD}>{t_i18n('Custom period')}</SelectItem>
          {extraPresets.map((preset) => (
            <SelectItem key={preset.key} value={preset.key}>{preset.label}</SelectItem>
          ))}
          {TIME_MACHINE_PRESETS.map((preset) => (
            <SelectItem key={preset} value={preset}>{t_i18n(presetLabel(preset))}</SelectItem>
          ))}
        </SelectContent>
      </Select>
      <DateTimePicker
        label={t_i18n('From')}
        value={new Date(value.from)}
        maxDateTime={new Date(value.to)}
        onAccept={(date) => handleDate('from', date)}
        slotProps={{ textField: { inputProps: { 'aria-label': t_i18n('From') } } }}
      />
      <DateTimePicker
        label={t_i18n('To')}
        value={new Date(value.to)}
        minDateTime={new Date(value.from)}
        disableFuture
        onAccept={(date) => handleDate('to', date)}
        slotProps={{ textField: { inputProps: { 'aria-label': t_i18n('To') } } }}
      />
    </Box>
  );
};

export default TimeMachinePeriodSelector;
