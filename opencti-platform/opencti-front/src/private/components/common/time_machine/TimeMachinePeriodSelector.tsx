import React, { ReactNode, useState } from 'react';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@filigran/design-system';
import { Box } from '@mui/material';
import DateTimePicker from '../../../../components/common/input/DateTimePicker';
import { useFormatter } from '../../../../components/i18n';
import { DateRange, presetLabel, presetRange, TIME_MACHINE_PRESETS, TimeMachinePreset, toComparableRange } from './timeMachineUtils';

export const CUSTOM_PERIOD = 'custom';

interface TimeMachinePeriodSelectorProps {
  value: DateRange;
  onChange: (range: DateRange) => void;
  initialPreset?: string;
  // Selected preset when the parent controls it, for instance to apply a preset from an empty state
  preset?: string;
  onPresetChange?: (preset: string) => void;
  // Extra preset relative to the user, for instance the date of the last visit
  extraPresets?: Array<{ key: string; label: string; range: DateRange }>;
  // Actions of the period toolbar, on its right
  actions?: ReactNode;
}

const TimeMachinePeriodSelector = ({
  value,
  onChange,
  initialPreset = CUSTOM_PERIOD,
  preset,
  onPresetChange,
  extraPresets = [],
  actions,
}: TimeMachinePeriodSelectorProps) => {
  const { t_i18n } = useFormatter();
  const [ownPresetKey, setOwnPresetKey] = useState(initialPreset);
  const presetKey = preset ?? ownPresetKey;
  const setPresetKey = (key: string) => {
    setOwnPresetKey(key);
    onPresetChange?.(key);
  };
  const handlePreset = (key: string) => {
    setPresetKey(key);
    if (key === CUSTOM_PERIOD) return;
    const extra = extraPresets.find((item) => item.key === key);
    onChange(extra ? extra.range : presetRange(key as TimeMachinePreset));
  };
  const handleDate = (field: keyof DateRange, date: Date | null) => {
    if (!date || Number.isNaN(date.getTime())) return;
    // The pickers accept equal ends; the diff APIs need a start strictly before the end
    const next = toComparableRange(field === 'from' ? date.toISOString() : value.from, field === 'to' ? date.toISOString() : value.to);
    if (next) {
      setPresetKey(CUSTOM_PERIOD);
      onChange(next);
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
          {extraPresets.map((item) => (
            <SelectItem key={item.key} value={item.key}>{item.label}</SelectItem>
          ))}
          {TIME_MACHINE_PRESETS.map((item) => (
            <SelectItem key={item} value={item}>{t_i18n(presetLabel(item))}</SelectItem>
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
      {actions && <Box sx={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 1 }}>{actions}</Box>}
    </Box>
  );
};

export default TimeMachinePeriodSelector;
