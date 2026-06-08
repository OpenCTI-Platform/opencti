import React from 'react';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import DatePicker from '@common/input/DatePicker';
import { parse, buildDate } from 'src/utils/Time';
import { InvestigationGraph_fragment$data } from '@components/workspaces/investigations/__generated__/InvestigationGraph_fragment.graphql';
import { EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import { useFormatter } from '../../../../components/i18n';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import { Dashboard_workspace$data } from './__generated__/Dashboard_workspace.graphql';
import { Stack } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Theme } from '../../../../components/Theme';

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
  config = {
    startDate: null,
    endDate: null,
    relativeDate: null,
  },
  handleDateChange,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { canEdit } = useGetCurrentUserAccessRight(workspace.currentUserAccessRight);

  const handleChangeRelativeDate = (event: SelectChangeEvent) => {
    const { value } = event.target;
    handleDateChange('relativeDate', value);
  };

  const startDateValue = buildDate(config.startDate);
  const endDateValue = buildDate(config.endDate);
  const minEndDate = startDateValue ? parse(startDateValue).startOf('day').toDate() : null;
  const maxStartDate = endDateValue ? parse(endDateValue).startOf('day').toDate() : null;

  const isBeforeDay = (date: Date, reference: Date) => (
    parse(date).startOf('day').isBefore(parse(reference).startOf('day'))
  );

  const isAfterDay = (date: Date, reference: Date) => (
    parse(date).startOf('day').isAfter(parse(reference).startOf('day'))
  );

  const handleChangeDate = (type: 'startDate' | 'endDate', value: Date | null) => {
    if (value && type === 'startDate' && maxStartDate && isAfterDay(value, maxStartDate)) {
      return;
    }
    if (value && type === 'endDate' && minEndDate && isBeforeDay(value, minEndDate)) {
      return;
    }
    const formattedDate = value ? parse(value).format() : null;
    handleDateChange(type, formattedDate);
  };

  return (
    <Security
      needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]}
      hasAccess={canEdit}
    >
      <Stack direction="row" gap={1}>
        <FormControl
          size="small"
          style={{ width: 194, marginInlineStart: 20 }}
        >
          <InputLabel
            id="relative"
          >
            {t_i18n('Relative time')}
          </InputLabel>
          <Select
            labelId="relative"
            value={config.relativeDate ?? ''}
            onChange={handleChangeRelativeDate}
            label={t_i18n('Relative time')}
            sx={{
              '& fieldset': {
                border: config.relativeDate
                  ? `1px solid ${theme.palette.border.secondary}`
                  : undefined,
              },
            }}
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
          value={startDateValue}
          label={t_i18n('Start date')}
          disableFuture
          disabled={!!config.relativeDate}
          maxDate={maxStartDate ?? undefined}
          onChange={(value: Date | null, context) => !context.validationError && handleChangeDate('startDate', value)}
        />
        <DatePicker
          value={endDateValue}
          label={t_i18n('End date')}
          disabled={!!config.relativeDate}
          disableFuture
          minDate={minEndDate ?? undefined}
          onChange={(value: Date | null, context) => !context.validationError && handleChangeDate('endDate', value)}
        />
      </Stack>
    </Security>
  );
};

export default DashboardTimeFilters;
