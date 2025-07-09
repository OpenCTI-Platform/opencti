import React, { Suspense } from 'react';
import Grid from '@mui/material/Grid2';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { useTheme } from '@mui/material/styles';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { PirOverviewCountsQuery, PirOverviewCountsQuery$variables } from './__generated__/PirOverviewCountsQuery.graphql';
import { PirOverviewCountsFragment$key } from './__generated__/PirOverviewCountsFragment.graphql';
import Loader from '../../../../components/Loader';
import Paper from '../../../../components/Paper';
import { useFormatter } from '../../../../components/i18n';
import { dayAgo } from '../../../../utils/Time';
import NumberDifference from '../../../../components/NumberDifference';
import type { Theme } from '../../../../components/Theme';

const countsFragment = graphql`
  fragment PirOverviewCountsFragment on Pir {
    id
  }
`;

const countsQuery = graphql`
  query PirOverviewCountsQuery($filters: FilterGroup, $startDate: DateTime) {
    stixRelationshipsDistribution(
      field: "entity_type",
      operation: count,
      filters: $filters
      startDate: $startDate
    ) {
      label
      value
    }
  }
`;

interface PirOverviewCountsComponentProps {
  countsQueryRef: PreloadedQuery<PirOverviewCountsQuery>
  counts24hQueryRef: PreloadedQuery<PirOverviewCountsQuery>
}

const PirOverviewCountsComponent = ({
  countsQueryRef,
  counts24hQueryRef,
}: PirOverviewCountsComponentProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();
  const resultAll = usePreloadedQuery(countsQuery, countsQueryRef);
  const result24h = usePreloadedQuery(countsQuery, counts24hQueryRef);

  const data = resultAll.stixRelationshipsDistribution?.flatMap((distribution) => {
    if (!distribution || distribution.label === 'Pir') return [];
    return distribution;
  });
  const data24h = result24h.stixRelationshipsDistribution?.flatMap((distribution) => {
    if (!distribution || distribution.label === 'Pir') return [];
    return distribution;
  });

  return (
    <Grid container spacing={3}>
      {data?.map(({ label, value }) => (
        <Grid key={label} size={{ xs: 3 }}>
          <Paper
            title={t_i18n(`entity_${label}`)}
            style={{
              display: 'flex',
              alignItems: 'flex-end',
              gap: theme.spacing(2),
            }}
          >
            <div style={{ fontSize: 40, lineHeight: 1 }}>{n(value)}</div>
            <NumberDifference
              value={data24h?.find((d) => d.label === label)?.value ?? 0}
              description={t_i18n('24 hours')}
            />
          </Paper>
        </Grid>
      ))}
    </Grid>
  );
};

interface PirOverviewCountsProps {
  data: PirOverviewCountsFragment$key
}

const PirOverviewCounts = ({ data }: PirOverviewCountsProps) => {
  const { id } = useFragment(countsFragment, data);

  const filters: PirOverviewCountsQuery$variables['filters'] = {
    mode: 'and',
    filterGroups: [],
    filters: [
      {
        key: ['relationship_type'],
        values: ['in-pir'],
      },
      {
        key: ['toId'],
        values: [id],
      },
    ],
  };
  const countsQueryRef = useQueryLoading<PirOverviewCountsQuery>(
    countsQuery,
    { filters },
  );
  const counts24hQueryRef = useQueryLoading<PirOverviewCountsQuery>(
    countsQuery,
    { filters, startDate: dayAgo() },
  );

  return (
    <Suspense fallback={<Loader />}>
      {countsQueryRef && counts24hQueryRef && (
        <PirOverviewCountsComponent
          countsQueryRef={countsQueryRef}
          counts24hQueryRef={counts24hQueryRef}
        />
      )}
    </Suspense>
  );
};

export default PirOverviewCounts;
