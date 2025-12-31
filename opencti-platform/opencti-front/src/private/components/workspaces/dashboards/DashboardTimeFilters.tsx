import React from 'react';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { parse, buildDate } from 'src/utils/Time';
import { InvestigationGraph_fragment$data } from '@components/workspaces/investigations/__generated__/InvestigationGraph_fragment.graphql';
import { EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import { useFormatter } from '../../../../components/i18n';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import { Dashboard_workspace$data } from './__generated__/Dashboard_workspace.graphql';

interface DashboardTimeFiltersProps {
  workspace: Dashboard_workspace$data | InvestigationGraph_fragment$data;
  config?: {
    startDate: string | null;
    endDate: string | null;
    relativeDate: string | null;
  };
  handleDateChange: (type: 'startDate' | 'endDate' | 'relativeDate', value: string | null) => void;
}

const DashboardTimeFilters: React.FC<DashboardTimeFiltersProps> = ({
  workspace,
  config = {},
  handleDateChange,
}) => {
  const { t_i18n } = useFormatter();
  const { canEdit } = useGetCurrentUserAccessRight(workspace.currentUserAccessRight);

  const handleChangeRelativeDate = (event: SelectChangeEvent) => {
    const { value } = event.target;
    handleDateChange('relativeDate', value);
  };

  const handleChangeDate = (type: 'startDate' | 'endDate', value: Date | null) => {
    const formattedDate = value ? parse(value).format() : null;
    handleDateChange(type, formattedDate);
  };

  return (
    <Security
      needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]}
      hasAccess={canEdit}
    >
      <div style={{ display: 'flex', marginLeft: 20 }}>
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
            onChange={handleChangeRelativeDate}
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
          value={buildDate(config.startDate)}
          label={t_i18n('Start date')}
          disableFuture
          disabled={!!config.relativeDate}
          onChange={(value: Date | null, context) => !context.validationError && handleChangeDate('startDate', value)}
          slotProps={{
            textField: {
              style: { marginRight: 8 },
              variant: 'outlined',
              size: 'small',
            },
          }}
        />
        <DatePicker
          value={buildDate(config.endDate)}
          label={t_i18n('End date')}
          disabled={!!config.relativeDate}
          disableFuture
          onChange={(value: Date | null, context) => !context.validationError && handleChangeDate('endDate', value)}
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
