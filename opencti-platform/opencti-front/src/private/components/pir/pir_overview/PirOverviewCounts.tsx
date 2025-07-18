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

interface PirOverviewCountProps {
  label: string
  value: number
  value24h: number
  size: number
}

const PirOverviewCount = ({ label, value, value24h, size }: PirOverviewCountProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();

  return (
    <Grid key={label} size={{ xs: size }}>
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
          value={value24h}
          description={t_i18n('24 hours')}
        />
      </Paper>
    </Grid>
  );
};

interface PirOverviewCountsComponentProps {
  countsQueryRef: PreloadedQuery<PirOverviewCountsQuery>
  counts24hQueryRef: PreloadedQuery<PirOverviewCountsQuery>
}

const PirOverviewCountsComponent = ({
  countsQueryRef,
  counts24hQueryRef,
}: PirOverviewCountsComponentProps) => {
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

  const malwares = data?.find((d) => d.label === 'Malware');
  const malwares24h = data24h?.find((d) => d.label === 'Malware');
  const campaigns = data?.find((d) => d.label === 'Campaign');
  const campaigns24h = data24h?.find((d) => d.label === 'Campaign');
  const instrusionSets = data?.find((d) => d.label === 'Intrusion-Set');
  const instrusionSets24h = data24h?.find((d) => d.label === 'Intrusion-Set');
  const threatActorIndividuals = data?.find((d) => d.label === 'Threat-Actor-Individual');
  const threatActorIndividuals24h = data24h?.find((d) => d.label === 'Threat-Actor-Individual');
  const threatActorGroups = data?.find((d) => d.label === 'Threat-Actor-Group');
  const threatActorGroups24h = data24h?.find((d) => d.label === 'Threat-Actor-Group');

  return (
    <Grid container spacing={3}>
      <PirOverviewCount
        size={4}
        label="Malware"
        value={malwares?.value ?? 0}
        value24h={malwares24h?.value ?? 0}
      />
      <PirOverviewCount
        size={4}
        label="Campaign"
        value={campaigns?.value ?? 0}
        value24h={campaigns24h?.value ?? 0}
      />
      <PirOverviewCount
        size={4}
        label="Intrusion-Set"
        value={instrusionSets?.value ?? 0}
        value24h={instrusionSets24h?.value ?? 0}
      />
      <PirOverviewCount
        size={6}
        label="Threat-Actor-Individual"
        value={threatActorIndividuals?.value ?? 0}
        value24h={threatActorIndividuals24h?.value ?? 0}
      />
      <PirOverviewCount
        size={6}
        label="Threat-Actor-Group"
        value={threatActorGroups?.value ?? 0}
        value24h={threatActorGroups24h?.value ?? 0}
      />
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
