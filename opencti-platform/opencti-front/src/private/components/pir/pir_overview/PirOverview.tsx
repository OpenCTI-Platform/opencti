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

import React from 'react';
import Box from '@mui/material/Box';
import Grid from '@mui/material/Grid2';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import PirThreatMap from './pir_threat_map/PirThreatMap';
import { pirHistoryFilterGroup } from '../pir-history-utils';
import PirOverviewCountFlagged from './PirOverviewCountFlagged';
import PirOverviewCounts from './PirOverviewCounts';
import PirOverviewTopSources from './PirOverviewTopSources';
import PirOverviewDetails from './PirOverviewDetails';
import PirOverviewHistory from './PirOverviewHistory';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { PirOverviewFragment$data, PirOverviewFragment$key } from './__generated__/PirOverviewFragment.graphql';
import { PirOverviewRedisStreamQuery } from './__generated__/PirOverviewRedisStreamQuery.graphql';
import { PirOverviewHistoryQuery } from './__generated__/PirOverviewHistoryQuery.graphql';
import { PirOverviewThreatMapQuery } from './__generated__/PirOverviewThreatMapQuery.graphql';

const overviewFragment = graphql`
  fragment PirOverviewFragment on Pir {
    id
    ...PirOverviewCountsFragment
    ...PirOverviewCountFlaggedFragment
    ...PirOverviewDetailsFragment
    ...PirOverviewHistoryPirFragment
    ...PirOverviewTopSourcesFragment
  }
`;

const redisStreamQuery = graphql`
  query PirOverviewRedisStreamQuery {
    ...PirOverviewDetailsRedisFragment
  }
`;

export const threatMapQuery = graphql`
  query PirOverviewThreatMapQuery($filters: FilterGroup, $pirId: ID!) {
    ...PirThreatMapFragment
  }
`;

const pirHistoryQuery = graphql`
  query PirOverviewHistoryQuery(
    $pirId: ID!
    $first: Int
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    ...PirOverviewHistoryFragment
  }
`;

interface PirOverviewComponentProps {
  pir: PirOverviewFragment$data;
  redisQueryRef: PreloadedQuery<PirOverviewRedisStreamQuery>;
  historyQueryRef: PreloadedQuery<PirOverviewHistoryQuery>;
  threatMapQueryRef: PreloadedQuery<PirOverviewThreatMapQuery>;
}

const PirOverviewComponent = ({
  pir,
  redisQueryRef,
  historyQueryRef,
  threatMapQueryRef,
}: PirOverviewComponentProps) => {
  const dataRedis = usePreloadedQuery(redisStreamQuery, redisQueryRef);
  const dataHistory = usePreloadedQuery(pirHistoryQuery, historyQueryRef);
  const dataThreatMap = usePreloadedQuery(threatMapQuery, threatMapQueryRef);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      {/* Threat intelligence summary */}
      <PirOverviewCounts data={pir} />

      {/* Core intelligence: activity feed + analytics */}
      <Grid container spacing={3}>
        <Grid size={{ xs: 12, lg: 8 }}>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            <PirOverviewCountFlagged data={pir} />
            <PirOverviewTopSources data={pir} />
          </Box>
        </Grid>
        <Grid size={{ xs: 12, lg: 4 }}>
          <Box sx={{ position: 'relative', height: '100%', minHeight: 360 }}>
            <Box sx={{ position: 'absolute', inset: 0 }}>
              <PirOverviewHistory dataHistory={dataHistory} dataPir={pir} />
            </Box>
          </Box>
        </Grid>
      </Grid>

      {/* Secondary, more technical visualisation */}
      <PirThreatMap data={dataThreatMap} />

      {/* Operational configuration, collapsed by default */}
      <PirOverviewDetails data={pir} dataStream={dataRedis} />
    </Box>
  );
};

interface PirOverviewProps {
  data: PirOverviewFragment$key;
}

const PirOverview = ({ data }: PirOverviewProps) => {
  const pir = useFragment(overviewFragment, data);

  const redisQueryRef = useQueryLoading<PirOverviewRedisStreamQuery>(redisStreamQuery);
  const pirHistoryQueryRef = useQueryLoading<PirOverviewHistoryQuery>(pirHistoryQuery, {
    first: 20,
    orderBy: 'timestamp',
    orderMode: 'desc',
    filters: pirHistoryFilterGroup,
    pirId: pir.id,
  });
  const threatMapQueryRef = useQueryLoading<PirOverviewThreatMapQuery>(threatMapQuery, {
    pirId: pir.id,
    filters: {
      mode: 'and',
      filterGroups: [],
      filters: [
        {
          key: ['regardingOf'],
          operator: 'eq',
          mode: 'and',
          values: [
            { key: 'id', values: [pir.id], operator: 'eq', mode: 'or' },
            { key: 'relationship_type', values: ['in-pir'], operator: 'eq', mode: 'or' },
          ],
        },
        {
          key: ['refreshed_at'],
          operator: 'within',
          values: ['now-7d', 'now'],
          mode: 'or',
        },
      ],
    },
  });

  if (!redisQueryRef || !pirHistoryQueryRef || !threatMapQueryRef) {
    return null;
  }

  return (
    <PirOverviewComponent
      pir={pir}
      redisQueryRef={redisQueryRef}
      historyQueryRef={pirHistoryQueryRef}
      threatMapQueryRef={threatMapQueryRef}
    />
  );
};

export default PirOverview;
