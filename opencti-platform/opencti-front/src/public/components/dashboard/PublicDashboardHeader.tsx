import Typography from '@mui/material/Typography';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import FormControl from '@mui/material/FormControl';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { useFormatter } from '../../../components/i18n';
import type { DashboardConfig } from '../../../components/dashboard/dashboard-types';
import { DASHBOARD_RELATIVE_DATE_OPTIONS } from '../../../components/dashboard/dashboard-time-filter-options';
import { buildDate } from '../../../utils/Time';
import type { ReactNode } from 'react';

interface PublicDashboardHeaderProps {
  title: string;
  manifestConfig: DashboardConfig;
  onChangeRelativeDate: (value: string) => void;
  onChangeStartDate: (value: string | null) => void;
  onChangeEndDate: (value: string | null) => void;
  actions?: ReactNode;
}

const PublicDashboardHeader = ({
  title,
  manifestConfig,
  onChangeRelativeDate,
  onChangeStartDate,
  onChangeEndDate,
  actions,
}: PublicDashboardHeaderProps) => {
  const { t_i18n } = useFormatter();
  const { relativeDate, startDate, endDate } = manifestConfig;

  return (
    <header
      style={{
        margin: '20px 20px 0 20px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        gap: '16px',
        flexWrap: 'wrap',
      }}
    >
      <div style={{ display: 'flex', gap: '16px', alignItems: 'center', flexWrap: 'wrap' }}>
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
            onChange={(event) => onChangeRelativeDate(event.target.value)}
            variant="outlined"
            disabled
          >
            {DASHBOARD_RELATIVE_DATE_OPTIONS.map((option) => (
              <MenuItem key={option.value} value={option.value}>
                {t_i18n(option.label)}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <DatePicker
          disabled
          value={buildDate(startDate)}
          label={t_i18n('Start date')}
          sx={{ width: 220 }}
          disableFuture
          onChange={(value, context) => !context.validationError && onChangeStartDate(value?.toString() ?? null)}
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
          value={buildDate(endDate)}
          label={t_i18n('End date')}
          disableFuture
          onChange={(value, context) => !context.validationError && onChangeEndDate(value?.toString() ?? null)}
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
      </div>
      {actions}
    </header>
  );
};

export default PublicDashboardHeader;
