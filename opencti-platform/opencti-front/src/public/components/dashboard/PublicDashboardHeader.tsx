import Typography from '@mui/material/Typography';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { useFormatter } from '../../../components/i18n';
import type { DashboardConfig } from '../../../components/dashboard/dashboard-types';
import DashboardRelativeDateSelect from '../../../components/dashboard/DashboardRelativeDateSelect';
import { buildDate, parse } from '../../../utils/Time';
import type { ReactNode } from 'react';
import Button from '@common/button/Button';

interface PublicDashboardHeaderProps {
  title: string;
  manifestConfig: DashboardConfig;
  onChangeRelativeDate: (value: string) => void;
  onChangeStartDate: (value: string | null) => void;
  onChangeEndDate: (value: string | null) => void;
  actions?: ReactNode;
  // The author allowed viewers to edit the time filters: the pickers are enabled.
  editable?: boolean;
  // Back to the published range, offered once the visitor changed it.
  onReset?: () => void;
}

const PublicDashboardHeader = ({
  title,
  manifestConfig,
  onChangeRelativeDate,
  onChangeStartDate,
  onChangeEndDate,
  actions,
  editable = false,
  onReset,
}: PublicDashboardHeaderProps) => {
  const { t_i18n } = useFormatter();
  const { relativeDate, startDate, endDate } = manifestConfig;
  // The pickers give a Date: stored as the private dashboard stores its dates.
  const toValue = (value: Date | null) => (value ? parse(value).format() : null);

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
          disabled={!editable}
        />
        <DatePicker
          disabled={!editable}
          value={buildDate(startDate)}
          label={t_i18n('Start date')}
          sx={{ width: 220 }}
          disableFuture
          onChange={(value, context) => !context.validationError && onChangeStartDate(toValue(value))}
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
          disabled={!editable}
          value={buildDate(endDate)}
          label={t_i18n('End date')}
          disableFuture
          onChange={(value, context) => !context.validationError && onChangeEndDate(toValue(value))}
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
        {onReset && (
          <Button variant="tertiary" size="small" onClick={onReset} data-testid="public-dashboard-reset-range">
            {t_i18n('Reset')}
          </Button>
        )}
      </div>
      {actions}
    </header>
  );
};

export default PublicDashboardHeader;
