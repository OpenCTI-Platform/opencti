import React from 'react';
import DatePicker from '@common/input/DatePicker';
import { parse, buildDate } from '../../utils/Time';
import { useFormatter } from '../i18n';
import { Stack } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Theme } from '../Theme';
import { DashboardConfig } from './dashboard-types';
import { EXPORT_KEEP_CLASS, EXPORT_REMOVE_CLASS } from '../../utils/Image';
import DashboardRelativeDateSelect from './DashboardRelativeDateSelect';

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

  return (
    <Stack direction="row" gap={1}>
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
        value={buildDate(config.startDate)}
        label={t_i18n('Start date')}
        disableFuture
        disabled={!!config.relativeDate}
        className={config.startDate ? EXPORT_KEEP_CLASS : EXPORT_REMOVE_CLASS}
        onChange={(value: Date | null, context) => !context.validationError && handleChangeDate('startDate', value)}
      />
      <DatePicker
        value={buildDate(config.endDate)}
        label={t_i18n('End date')}
        disabled={!!config.relativeDate}
        disableFuture
        className={config.endDate ? EXPORT_KEEP_CLASS : EXPORT_REMOVE_CLASS}
        onChange={(value: Date | null, context) => !context.validationError && handleChangeDate('endDate', value)}
      />
    </Stack>
  );
};

export default DashboardTimeFilters;
