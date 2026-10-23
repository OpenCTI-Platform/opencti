import React, { useState } from 'react';
import DatePicker from '@common/input/DatePicker';
import { DateValidationError, PickerChangeHandlerContext } from '@mui/x-date-pickers/models';
import { parse, buildDate } from '../../utils/Time';
import { useFormatter } from '../i18n';
import { Stack } from '@mui/material';
import { useTheme } from '@mui/styles';
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
const useDateDraft = (date: string | null | undefined, onValidChange: (value: Date | null) => void) => {
  const [draft, setDraft] = useState(() => buildDate(date));
  const [draftSource, setDraftSource] = useState(date);
  if (date !== draftSource) {
    setDraftSource(date);
    setDraft(buildDate(date));
  }
  const onChange = (value: Date | null, context: PickerChangeHandlerContext<DateValidationError>) => {
    setDraft(value);
    if (!context.validationError) {
      onValidChange(value);
    }
  };
  return { value: draft, onChange };
};

interface DashboardTimeFiltersProps {
  config?: DashboardConfig;
  handleDateChange: (type: 'startDate' | 'endDate' | 'relativeDate', value: string | null) => void;
}

const DashboardTimeFilters: React.FC<DashboardTimeFiltersProps> = ({
  config = {
    startDate: null,
    endDate: null,
    relativeDate: null,
  },
  handleDateChange,
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
  const startDate = useDateDraft(config.startDate, (value) => handleChangeDate('startDate', value));
  const endDate = useDateDraft(config.endDate, (value) => handleChangeDate('endDate', value));

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
