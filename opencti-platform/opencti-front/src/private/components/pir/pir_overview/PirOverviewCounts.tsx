/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { CSSProperties, Suspense } from 'react';
import Grid from '@mui/material/Grid2';
import Typography from '@mui/material/Typography';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { useTheme } from '@mui/material/styles';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { PirOverviewCountsQuery } from './__generated__/PirOverviewCountsQuery.graphql';
import { PirOverviewCountsFragment$key } from './__generated__/PirOverviewCountsFragment.graphql';
import Paper from '../../../../components/Paper';
import { useFormatter } from '../../../../components/i18n';
import { dayAgo } from '../../../../utils/Time';
import NumberDifference from '../../../../components/NumberDifference';
import type { Theme } from '../../../../components/Theme';
import ItemIcon from '../../../../components/ItemIcon';

const PirOverviewCountsDummy = () => {
  const theme = useTheme<Theme>();
  const dummyStyle: CSSProperties = {
    height: 97,
    background: theme.palette.background.paper,
  };
  return (
    <>
      <Grid size={{ xs: 3 }} style={dummyStyle}></Grid>
      <Grid size={{ xs: 3 }} style={dummyStyle}></Grid>
      <Grid size={{ xs: 3 }} style={dummyStyle}></Grid>
      <Grid size={{ xs: 3 }} style={dummyStyle}></Grid>
    </>
  );
};

const countsFragment = graphql`
  fragment PirOverviewCountsFragment on Pir {
    id
  }
`;

const countsQuery = graphql`
  query PirOverviewCountsQuery($pirId: ID!, $startDate: DateTime) {
    pirRelationshipsDistribution(
      field: "entity_type",
      operation: count,
      startDate: $startDate
      relationship_type: "in-pir"
      pirId: $pirId
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
}

const PirOverviewCount = ({ label, value, value24h }: PirOverviewCountProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();

  return (
    <Grid key={label} size={{ xs: 3 }}>
      <Paper style={{ padding: theme.spacing(1.5), paddingTop: theme.spacing(1) }}>
        <div style={{ display: 'flex', alignItems: 'start' }}>
          <Typography
            color={theme.palette.text?.secondary}
            sx={{ marginTop: 0.5, textTransform: 'uppercase', flex: 1 }}
            variant="body2"
            gutterBottom
          >
            {t_i18n(`entity_${label}`)}
          </Typography>
          <ItemIcon type={label} size='large' />
        </div>

        <div style={{
          display: 'flex',
          alignItems: 'flex-end',
          gap: theme.spacing(1),
        }}
        >
          <div
            data-testid={`pir-overview-count-${label}`}
            style={{ fontSize: 40, lineHeight: 1 }}
          >
            {n(value)}
          </div>
          <NumberDifference
            value={value24h}
            description={t_i18n('24 hours')}
          />
        </div>
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

  const data = resultAll.pirRelationshipsDistribution?.flatMap((distribution) => {
    if (!distribution || distribution.label === 'Pir') return [];
    return distribution;
  });
  const data24h = result24h.pirRelationshipsDistribution?.flatMap((distribution) => {
    if (!distribution || distribution.label === 'Pir') return [];
    return distribution;
  });

  const malwares = data?.find((d) => d.label === 'Malware')?.value ?? 0;
  const malwares24h = data24h?.find((d) => d.label === 'Malware')?.value ?? 0;
  const campaigns = data?.find((d) => d.label === 'Campaign')?.value ?? 0;
  const campaigns24h = data24h?.find((d) => d.label === 'Campaign')?.value ?? 0;
  const instrusionSets = data?.find((d) => d.label === 'Intrusion-Set')?.value ?? 0;
  const instrusionSets24h = data24h?.find((d) => d.label === 'Intrusion-Set')?.value ?? 0;
  const threatActorIndividuals = data?.find((d) => d.label === 'Threat-Actor-Individual')?.value ?? 0;
  const threatActorIndividuals24h = data24h?.find((d) => d.label === 'Threat-Actor-Individual')?.value ?? 0;
  const threatActorGroups = data?.find((d) => d.label === 'Threat-Actor-Group')?.value ?? 0;
  const threatActorGroups24h = data24h?.find((d) => d.label === 'Threat-Actor-Group')?.value ?? 0;
  const threatActor = threatActorIndividuals + threatActorGroups;
  const threatActor24h = threatActorIndividuals24h + threatActorGroups24h;

  return (
    <>
      <PirOverviewCount
        label="Malware"
        value={malwares}
        value24h={malwares24h}
      />
      <PirOverviewCount
        label="Campaign"
        value={campaigns}
        value24h={campaigns24h}
      />
      <PirOverviewCount
        label="Intrusion-Set"
        value={instrusionSets}
        value24h={instrusionSets24h}
      />
      <PirOverviewCount
        label="Threat-Actor"
        value={threatActor}
        value24h={threatActor24h}
      />
    </>
  );
};

interface PirOverviewCountsProps {
  data: PirOverviewCountsFragment$key
}

const PirOverviewCounts = ({ data }: PirOverviewCountsProps) => {
  const { t_i18n } = useFormatter();
  const { id: pirId } = useFragment(countsFragment, data);

  const countsQueryRef = useQueryLoading<PirOverviewCountsQuery>(
    countsQuery,
    { pirId },
  );
  const counts24hQueryRef = useQueryLoading<PirOverviewCountsQuery>(
    countsQuery,
    { pirId, startDate: dayAgo() },
  );

  return (
    <Grid size={{ xs: 12 }}>
      <Typography variant="h4">
        {t_i18n('Number of threats')}
      </Typography>
      <Grid container spacing={3}>
        <Suspense fallback={<PirOverviewCountsDummy />}>
          {countsQueryRef && counts24hQueryRef && (
          <PirOverviewCountsComponent
            countsQueryRef={countsQueryRef}
            counts24hQueryRef={counts24hQueryRef}
          />
          )}
        </Suspense>
      </Grid>
    </Grid>
  );
};

export default PirOverviewCounts;
