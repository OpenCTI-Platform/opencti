import React, { Suspense } from 'react';
import Grid from '@mui/material/Grid2';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { PirOverviewCountsQuery } from './__generated__/PirOverviewCountsQuery.graphql';
import { PirOverviewCountsFragment$key } from './__generated__/PirOverviewCountsFragment.graphql';
import Loader from '../../../../components/Loader';
import Paper from '../../../../components/Paper';
import { useFormatter } from '../../../../components/i18n';

const countsFragment = graphql`
  fragment PirOverviewCountsFragment on Pir {
    id
  }
`;

const countsQuery = graphql`
  query PirOverviewCountsQuery($filters: FilterGroup) {
    stixRelationshipsDistribution(
      field: "entity_type",
      operation: count,
      filters: $filters
    ) {
      label
      value
    }
  }
`;

interface PirOverviewCountsComponentProps {
  countsQueryRef: PreloadedQuery<PirOverviewCountsQuery>
}

const PirOverviewCountsComponent = ({ countsQueryRef }: PirOverviewCountsComponentProps) => {
  const { t_i18n, n } = useFormatter();
  const { stixRelationshipsDistribution } = usePreloadedQuery(countsQuery, countsQueryRef);

  const data = stixRelationshipsDistribution?.flatMap((distribution) => {
    if (!distribution || distribution.label === 'Pir') return [];
    return distribution;
  });

  return (
    <Grid container spacing={3}>
      {data?.map(({ label, value }) => (
        <Grid key={label} size={{ xs: 3 }}>
          <Paper title={t_i18n(`entity_${label}`)}>
            <div style={{ fontSize: 40, lineHeight: 1 }}>{n(value)}</div>
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
  const countsQueryRef = useQueryLoading<PirOverviewCountsQuery>(
    countsQuery,
    {
      filters: {
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
      },
    },
  );

  return (
    <Suspense fallback={<Loader />}>
      {countsQueryRef && (
        <PirOverviewCountsComponent countsQueryRef={countsQueryRef} />
      )}
    </Suspense>
  );
};

export default PirOverviewCounts;
