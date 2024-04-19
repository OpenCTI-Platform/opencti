import Typography from '@mui/material/Typography';
import React from 'react';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import FormControl from '@mui/material/FormControl';
import { DatePicker } from '@mui/x-date-pickers';
import { useFormatter } from '../../../components/i18n';
import type { PublicManifestConfig } from './PublicManifest';

interface PublicDashboardHeaderProps {
  title: string
  manifestConfig: PublicManifestConfig
}

const PublicDashboardHeader = ({
  title,
  manifestConfig,
}: PublicDashboardHeaderProps) => {
  const { t_i18n } = useFormatter();
  const { relativeDate, startDate, endDate } = manifestConfig;

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
        sx={{ marginRight: '12px' }}
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
        value={startDate ? new Date(startDate) : null}
        label={t_i18n('Start date')}
        sx={{ width: 220 }}
        disableFuture
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
        value={endDate ? new Date(endDate) : null}
        label={t_i18n('End date')}
        disableFuture
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
