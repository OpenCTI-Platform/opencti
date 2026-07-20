import React from 'react';
import type { Theme } from '../../../../../../components/Theme';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import Grid from '@mui/material/Grid2';
import SummaryCard from './SummaryCard';
import { useFormatter } from '../../../../../../components/i18n';
import SummaryRecords from './SummaryRecords';
import WidgetHorizontalBars from '../../../../../../components/dashboard/WidgetHorizontalBars';
import { SearchAnalyticsQuery } from './__generated__/SearchAnalyticsQuery.graphql';

const useStyles = makeStyles<Theme>(() => ({
  countCard: {
    flex: 1,
    display: 'flex',
    alignItems: 'center',
    fontSize: '24px',
  },
}));

export const searchAnalyticsQuery = graphql`
  query SearchAnalyticsQuery(
    $first: Int
    $startDate: DateTime
    $endDate: DateTime
    $binSize: Int
    $minBin: Int
    $maxBin: Int
  ) {
    searchAnalytics(
      first: $first
      startDate: $startDate
      endDate: $endDate
      binSize: $binSize
      minBin: $minBin
      maxBin: $maxBin
    )
    {
      summary {
        total_searches,
        total_locations,
        total_organizations,
        total_users
      },
      locations {
        value,
        count
      },
      organizations {
        value,
        count
      },
      searchCounts {
        value,
        count
      },
      withResults {
        value,
        count
      },
      noResults {
        value,
        count
      }
    }
  }
`;

interface SearchAnalyticsProps {
  queryRef: PreloadedQuery<SearchAnalyticsQuery>;
}

const SearchAnalytics = ({
  queryRef,
}: SearchAnalyticsProps) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const { searchAnalytics } = usePreloadedQuery(searchAnalyticsQuery, queryRef);

  const getSeries = () => {
    const graph_raw_data = searchAnalytics?.searchCounts;
    const data = [];
    for (const bin_count of graph_raw_data ?? []) {
      data.push({ x: bin_count?.value, y: bin_count?.count });
    }
    return [{ data: data, name: 'Number of results' }];
  };
  return (
    <Grid container spacing={2}>
      <Grid container size={12} spacing={2}>

        <SummaryCard title={t_i18n('Searches')} size={3} height={100}>
          <div className={classes.countCard}>
            {searchAnalytics?.summary.total_searches}
          </div>
        </SummaryCard>

        <SummaryCard title={t_i18n('Locations')} size={3} height={100}>
          <div className={classes.countCard}>
            {searchAnalytics?.summary.total_locations}
          </div>
        </SummaryCard>

        <SummaryCard title={t_i18n('Organizations')} size={3} height={100}>
          <div className={classes.countCard}>
            {searchAnalytics?.summary.total_organizations}
          </div>
        </SummaryCard>

        <SummaryCard title={t_i18n('Users')} size={3} height={100}>
          <div className={classes.countCard}>
            {searchAnalytics?.summary.total_users}
          </div>
        </SummaryCard>
      </Grid>
      <Grid container size={12}>
        <SummaryCard title={t_i18n('Search result count distribution')} size={4} height={200} padding={0}>
          <div style={{ height: '100%', width: '100%', overflow: 'hidden' }}>
            <WidgetHorizontalBars
              series={getSeries()}
              distributed={false}
            />
          </div>

        </SummaryCard>
        <SummaryCard title={t_i18n('Locations')} size={4} height={200}>
          <SummaryRecords records={[...searchAnalytics?.locations ?? []]} />
        </SummaryCard>
        <SummaryCard title={t_i18n('Organizations')} size={4} height={200}>
          <SummaryRecords records={[...searchAnalytics?.organizations ?? []]} />
        </SummaryCard>
      </Grid>
      <Grid container size={12}>
        <SummaryCard title={t_i18n('Top 10 searches with no results (#)')} size={6} height={325}>
          <SummaryRecords records={[...searchAnalytics?.noResults ?? []]} />
        </SummaryCard>
        <SummaryCard title={t_i18n('Top 10 searches with results (#)')} size={6} height={325}>
          <SummaryRecords records={[...searchAnalytics?.withResults ?? []]} />
        </SummaryCard>
      </Grid>
    </Grid>
  );
};

export default SearchAnalytics;
