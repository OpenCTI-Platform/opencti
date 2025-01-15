import React from 'react';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import { useFormatter } from '../../../../components/i18n';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import { Dashboard_workspace$data } from './__generated__/Dashboard_workspace.graphql';

interface DashboardTimeFiltersProps {
  workspace: Dashboard_workspace$data
  config?: {
    startDate: object
    endDate: object
    relativeDate: string
  }
  handleDateChange: (bound: 'startDate' | 'endDate' | 'relativeDate', value: object | string | null) => unknown
}

const DashboardTimeFilters: React.FC<DashboardTimeFiltersProps> = ({
  workspace,
  config = {},
  handleDateChange,
}) => {
  const { t_i18n } = useFormatter();
  const { canEdit } = useGetCurrentUserAccessRight(workspace.currentUserAccessRight);

  return (
    <Security
      needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]}
      hasAccess={canEdit}
    >
      <div style={{ display: 'flex', marginLeft: 20 }} >
        <FormControl
          size="small"
          style={{ width: 194, marginRight: 8 }}
          variant="outlined"
        >
          <InputLabel id="relative" variant="outlined">
            {t_i18n('Relative time')}
          </InputLabel>
          <Select
            labelId="relative"
            value={config.relativeDate ?? ''}
            onChange={(value) => handleDateChange('relativeDate', value)}
            label={t_i18n('Relative time')}
            variant="outlined"
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
          value={config.startDate ?? null}
          label={t_i18n('Start date')}
          disableFuture={true}
          disabled={!!config.relativeDate}
          onChange={(value, context) => !context.validationError && handleDateChange('startDate', value)}
          slotProps={{
            textField: {
              style: { marginRight: 8 },
              variant: 'outlined',
              size: 'small',
            },
          }}
        />
        <DatePicker
          value={config.endDate ?? null}
          label={t_i18n('End date')}
          disabled={!!config.relativeDate}
          disableFuture={true}
          onChange={(value, context) => !context.validationError && handleDateChange('endDate', value)}
          slotProps={{
            textField: {
              variant: 'outlined',
              size: 'small',
            },
          }}
        />
      </div>
    </Security>
  );
};

export default DashboardTimeFilters;
