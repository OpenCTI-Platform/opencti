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
import Grid from '@mui/material/Grid2';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
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
  pir: PirOverviewFragment$data
  redisQueryRef: PreloadedQuery<PirOverviewRedisStreamQuery>
  historyQueryRef: PreloadedQuery<PirOverviewHistoryQuery>
}

const PirOverviewComponent = ({
  pir,
  redisQueryRef,
  historyQueryRef,
}: PirOverviewComponentProps) => {
  const dataRedis = usePreloadedQuery(redisStreamQuery, redisQueryRef);
  const dataHistory = usePreloadedQuery(pirHistoryQuery, historyQueryRef);

  return (
    <Grid container spacing={3}>
      <Grid size={{ xs: 12 }} container direction='column' spacing={3}>
        <PirOverviewDetails data={pir} dataStream={dataRedis} />
        <PirOverviewCounts data={pir} />
      </Grid>
      <Grid size={{ xs: 6 }} container direction='column' spacing={3}>
        <PirOverviewHistory dataHistory={dataHistory} dataPir={pir} />
      </Grid>
      <Grid size={{ xs: 6 }} container direction='column' spacing={3}>
        <PirOverviewTopSources data={pir} />
        <PirOverviewCountFlagged data={pir} />
      </Grid>
    </Grid>
  );
};

interface PirOverviewProps {
  data: PirOverviewFragment$key
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

  if (!redisQueryRef || !pirHistoryQueryRef) {
    return null;
  }

  return (
    <PirOverviewComponent
      pir={pir}
      redisQueryRef={redisQueryRef}
      historyQueryRef={pirHistoryQueryRef}
    />
  );
};

export default PirOverview;
