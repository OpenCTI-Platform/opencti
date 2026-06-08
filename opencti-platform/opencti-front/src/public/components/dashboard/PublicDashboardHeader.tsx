import Typography from '@mui/material/Typography';
import React from 'react';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import FormControl from '@mui/material/FormControl';
import { useFormatter } from '../../../components/i18n';
import type { PublicManifestConfig } from './PublicManifest';
import DatePicker from '../../../components/common/input/DatePicker';
import { buildDate, parse } from '../../../utils/Time';

interface PublicDashboardHeaderProps {
  title: string;
  manifestConfig: PublicManifestConfig;
  onChangeRelativeDate: (value: string) => void;
  onChangeStartDate: (value: string | null) => void;
  onChangeEndDate: (value: string | null) => void;
}

const PublicDashboardHeader = ({
  title,
  manifestConfig,
  onChangeRelativeDate,
  onChangeStartDate,
  onChangeEndDate,
}: PublicDashboardHeaderProps) => {
  const { t_i18n } = useFormatter();
  const { relativeDate, startDate, endDate } = manifestConfig;
  const startDateValue = buildDate(startDate);
  const endDateValue = buildDate(endDate);
  const minEndDate = startDateValue ? parse(startDateValue).startOf('day').toDate() : null;

  const isBeforeDay = (date: Date, reference: Date) => (
    parse(date).startOf('day').isBefore(parse(reference).startOf('day'))
  );

  return (
    <header style={{
      margin: '20px 20px 0 20px',
      display: 'flex',
      gap: '16px',
      alignItems: 'center',
    }}
    >
      <Typography
        variant="h1"
        gutterBottom={true}
        sx={{ marginInlineEnd: '12px' }}
      >
        {title}
      </Typography>

      <FormControl
        variant="outlined"
        size="small"
        style={{ width: 200 }}
      >
        <InputLabel id="relative" variant="outlined">
          {t_i18n('Relative time')}
        </InputLabel>
        <Select
          labelId="relative"
          label={t_i18n('Relative time')}
          value={relativeDate ?? ''}
          onChange={(event) => onChangeRelativeDate(event.target.value)}
          variant="outlined"
          disabled
        >
          <MenuItem value="none">{t_i18n('None')}</MenuItem>
          <MenuItem value="days-1">{t_i18n('Last 24 hours')}</MenuItem>
          <MenuItem value="days-7">{t_i18n('Last 7 days')}</MenuItem>
          <MenuItem value="months-1">{t_i18n('Last month')}</MenuItem>
          <MenuItem value="months-3">{t_i18n('Last 3 months')}</MenuItem>
          <MenuItem value="months-6">{t_i18n('Last 6 months')}</MenuItem>
          <MenuItem value="years-1">{t_i18n('Last year')}</MenuItem>
        </Select>
      </FormControl>
      <DatePicker
        disabled
        value={startDateValue}
        label={t_i18n('Start date')}
        sx={{ width: 220 }}
        disableFuture
        onChange={(value, context) => {
          if (context.validationError) return;
          onChangeStartDate(value?.toString() ?? null);
        }}
        slotProps={{
          field: {
            clearable: true,
          },
          textField: {
            variant: 'outlined',
            size: 'small',
          },
          toolbar: {
            hidden: true,
          },
        }}
      />
      <DatePicker
        disabled
        value={endDateValue}
        label={t_i18n('End date')}
        disableFuture
        minDate={minEndDate ?? undefined}
        onChange={(value, context) => {
          if (context.validationError) return;
          if (value && minEndDate && isBeforeDay(value, minEndDate)) return;
          onChangeEndDate(value?.toString() ?? null);
        }}
        sx={{ width: 220 }}
        slotProps={{
          field: {
            clearable: true,
          },
          textField: {
            variant: 'outlined',
            size: 'small',
          },
          toolbar: {
            hidden: true,
          },
        }}
      />
    </header>
  );
};

export default PublicDashboardHeader;
