import React from 'react';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import DatePicker from '@common/input/DatePicker';
import { parse, buildDate } from '../../utils/Time';
import { useFormatter } from '../i18n';
import { Stack } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Theme } from '../Theme';
import { DashboardConfig } from './dashboard-types';
import { EXPORT_KEEP_CLASS, EXPORT_REMOVE_CLASS } from '../../utils/Image';
import { DASHBOARD_RELATIVE_DATE_OPTIONS } from './dashboard-time-filter-options';

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

  const handleChangeRelativeDate = (event: SelectChangeEvent) => {
    const { value } = event.target;
    handleDateChange('relativeDate', value);
  };

  const handleChangeDate = (type: 'startDate' | 'endDate', value: Date | null) => {
    const formattedDate = value ? parse(value).format() : null;
    handleDateChange(type, formattedDate);
  };

  return (
    <Stack direction="row" gap={1}>
      <FormControl
        size="small"
        style={{ width: 194 }}
        variant="outlined"
        className={config.relativeDate ? EXPORT_KEEP_CLASS : EXPORT_REMOVE_CLASS}
      >
        <InputLabel
          id="relative"
          variant="outlined"
        >
          {t_i18n('Relative time')}
        </InputLabel>
        <Select
          labelId="relative"
          value={config.relativeDate ?? ''}
          onChange={handleChangeRelativeDate}
          label={t_i18n('Relative time')}
          variant="outlined"
          className={config.relativeDate ? EXPORT_KEEP_CLASS : undefined}
          sx={{
            '& fieldset': {
              border: config.relativeDate
                ? `1px solid ${theme.palette.border.secondary}`
                : undefined,
            },
          }}
        >
          {DASHBOARD_RELATIVE_DATE_OPTIONS.map((option) => (
            <MenuItem key={option.value} value={option.value}>
              {t_i18n(option.label)}
            </MenuItem>
          ))}
        </Select>
      </FormControl>
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
