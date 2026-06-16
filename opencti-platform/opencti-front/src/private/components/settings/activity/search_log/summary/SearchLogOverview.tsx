import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import type { Theme } from '../../../../../../components/Theme';
import useQueryLoading from '../../../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../../../utils/hooks/useConnectedDocumentModifier';
import InputLabel from '@mui/material/InputLabel';
import MenuItem from '@mui/material/MenuItem';
import FormControl from '@mui/material/FormControl';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import SearchAnalytics, { searchAnalyticsQuery } from './SearchAnalytics';
import SearchAnalyticsDummy from './SearchAnalyticsDummy';
import { SearchAnalyticsQuery } from './__generated__/SearchAnalyticsQuery.graphql';
// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const computeTargetDate = (dateRangeSpan: string) => {
  const currentDate = new Date();
  switch (dateRangeSpan) {
    case 'day':
      currentDate.setDate(currentDate.getDate() - 1);
      break;
    case 'week':
      currentDate.setDate(currentDate.getDate() - 7);
      break;
    case 'month':
      currentDate.setMonth(currentDate.getMonth() - 1);
      break;
    case 'year':
      currentDate.setFullYear(currentDate.getFullYear() - 1);
      break;
    default:
      // get all
      currentDate.setTime(0);
  }
  return { start: currentDate.toISOString(), end: new Date().toISOString() };
};

const SearchLogOverview = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Events | Activity | Settings'));
  const [dateRangeSpan, setDateRangeSpan] = React.useState<string>('month');
  const [dateRange, setDateRange] = React.useState<{ start: string; end: string }>(computeTargetDate('month'));

  const handleChange = (event: SelectChangeEvent) => {
    setDateRangeSpan(event.target.value as string);
    setDateRange(computeTargetDate(event.target.value as string));
  };

  const queryRef = useQueryLoading<SearchAnalyticsQuery>(
    searchAnalyticsQuery,
    {
      first: 10,
      startDate: dateRange.start,
      endDate: dateRange.end,
      binSize: 5,
      minBin: 0,
      maxBin: 25,
    },
  );

  return (
    <div className={classes.container} data-testid="search-log-overview-page">
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <FormControl fullWidth={true} style={{ flex: 1 }} variant="outlined">
          <InputLabel id="date-range-select-label" size="small">Date range</InputLabel>
          <Select
            style={{ width: 200 }}
            labelId="date-range-select-label"
            id="date-range-select"
            value={dateRangeSpan}
            onChange={handleChange}
            label="Date range"
            size="small"
            variant="outlined"
          >
            <MenuItem value="day">Past day</MenuItem>
            <MenuItem value="week">Past week</MenuItem>
            <MenuItem value="month">Past month</MenuItem>
            <MenuItem value="year">Past year</MenuItem>
            <MenuItem value="all">All</MenuItem>
          </Select>
        </FormControl>
        {queryRef && (
          <React.Suspense
            fallback={(
              <>
                <SearchAnalyticsDummy />
              </>
            )}
          >
            <SearchAnalytics
              queryRef={queryRef}
            />
          </React.Suspense>
        )}
      </div>
    </div>
  );
};

export default SearchLogOverview;
