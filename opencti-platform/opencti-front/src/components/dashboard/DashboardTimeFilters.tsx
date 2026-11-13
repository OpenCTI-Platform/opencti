import React, { useEffect, useRef, useState } from 'react';
import DatePicker from '@common/input/DatePicker';
import { DateValidationError, PickerChangeHandlerContext } from '@mui/x-date-pickers/models';
import { parse, buildDate } from '../../utils/Time';
import { useFormatter } from '../i18n';
import { Stack } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { Theme } from '../Theme';
import { DashboardConfig } from './dashboard-types';
import { EXPORT_KEEP_CLASS, EXPORT_REMOVE_CLASS } from '../../utils/Image';
import DashboardRelativeDateSelect from './DashboardRelativeDateSelect';

/**
 * Keeps the date shown in a picker while it is typed, and forwards only the valid ones.
 *
 * The picker field empties itself when the controlled value does not follow a date it
 * publishes. Typing a year goes through dates that fail validation (0002, 0020...), so the
 * value must still follow them, or the month and day typed before would be wiped.
 */
// Mirrors what the pickers refuse: a malformed date, or a day after today (they are disableFuture).
const isRefusedDate = (value: Date | null) => {
  if (value === null) return false;
  if (Number.isNaN(value.getTime())) return true;
  const endOfToday = new Date();
  endOfToday.setHours(23, 59, 59, 999);
  return value > endOfToday;
};

const useDateDraft = (
  date: string | null | undefined,
  onValidChange: (value: Date | null) => void,
  onInvalidChange?: (invalid: boolean) => void,
) => {
  const [draft, setDraft] = useState(() => buildDate(date));
  const [draftSource, setDraftSource] = useState(date);
  // Whether the date shown is one the picker refuses (malformed, or in the future): it is never forwarded, so a form
  // that holds the range must know the field does not show what it holds. A date given from outside (a stored range,
  // a preset) is checked as well: the picker shows it as refused without any change.
  const [invalid, setInvalid] = useState(() => isRefusedDate(buildDate(date)));
  if (date !== draftSource) {
    const next = buildDate(date);
    setDraftSource(date);
    setDraft(next);
    setInvalid(isRefusedDate(next));
  }
  const onInvalidChangeRef = useRef(onInvalidChange);
  onInvalidChangeRef.current = onInvalidChange;
  useEffect(() => {
    onInvalidChangeRef.current?.(invalid);
  }, [invalid]);
  const onChange = (value: Date | null, context: PickerChangeHandlerContext<DateValidationError>) => {
    setDraft(value);
    setInvalid(!!context.validationError);
    if (!context.validationError) {
      onValidChange(value);
    }
  };
  return { value: draft, onChange };
};

interface DashboardTimeFiltersProps {
  config?: DashboardConfig;
  handleDateChange: (type: 'startDate' | 'endDate' | 'relativeDate', value: string | null) => void;
  // Told when a date picker starts or stops showing a date it refuses, which is not forwarded.
  onInvalidDateChange?: (type: 'startDate' | 'endDate', invalid: boolean) => void;
}

const DashboardTimeFilters: React.FC<DashboardTimeFiltersProps> = ({
  config = {
    startDate: null,
    endDate: null,
    relativeDate: null,
  },
  handleDateChange,
  onInvalidDateChange,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const handleChangeRelativeDate = (value: string) => {
    handleDateChange('relativeDate', value);
  };

  const handleChangeDate = (type: 'startDate' | 'endDate', value: Date | null) => {
    const formattedDate = value ? parse(value).format() : null;
    handleDateChange(type, formattedDate);
  };
  const startDate = useDateDraft(config.startDate, (value) => handleChangeDate('startDate', value), (invalid) => onInvalidDateChange?.('startDate', invalid));
  const endDate = useDateDraft(config.endDate, (value) => handleChangeDate('endDate', value), (invalid) => onInvalidDateChange?.('endDate', invalid));

  return (
    <Stack
      direction="row"
      sx={{
        gap: 1,
      }}
    >
      <DashboardRelativeDateSelect
        value={config.relativeDate ?? ''}
        onChange={handleChangeRelativeDate}
        formControlClassName={config.relativeDate ? EXPORT_KEEP_CLASS : EXPORT_REMOVE_CLASS}
        selectClassName={config.relativeDate ? EXPORT_KEEP_CLASS : undefined}
        selectSx={{
          '& fieldset': {
            border: config.relativeDate
              ? `1px solid ${theme.palette.border.secondary}`
              : undefined,
          },
        }}
      />
      <DatePicker
        value={startDate.value}
        label={t_i18n('Start date')}
        disableFuture
        disabled={!!config.relativeDate}
        className={config.startDate ? EXPORT_KEEP_CLASS : EXPORT_REMOVE_CLASS}
        onChange={startDate.onChange}
      />
      <DatePicker
        value={endDate.value}
        label={t_i18n('End date')}
        disabled={!!config.relativeDate}
        disableFuture
        className={config.endDate ? EXPORT_KEEP_CLASS : EXPORT_REMOVE_CLASS}
        onChange={endDate.onChange}
      />
    </Stack>
  );
};

export default DashboardTimeFilters;
