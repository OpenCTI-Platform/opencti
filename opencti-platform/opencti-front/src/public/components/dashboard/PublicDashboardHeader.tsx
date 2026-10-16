import Typography from '@mui/material/Typography';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { useFormatter } from '../../../components/i18n';
import type { DashboardConfig } from '../../../components/dashboard/dashboard-types';
import DashboardRelativeDateSelect from '../../../components/dashboard/DashboardRelativeDateSelect';
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

        <DashboardRelativeDateSelect
          value={relativeDate ?? ''}
          onChange={onChangeRelativeDate}
          disabled
        />
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
