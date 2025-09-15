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
import PirOverviewCountFlagged from './PirOverviewCountFlagged';
import PirOverviewCounts from './PirOverviewCounts';
import PirOverviewTopSources from './PirOverviewTopSources';
import PirOverviewDetails from './PirOverviewDetails';
import PirOverviewHistory from './PirOverviewHistory';
import { PirQuery$data } from '../__generated__/PirQuery.graphql';
import { PirOverviewHistoryFragment$key } from './__generated__/PirOverviewHistoryFragment.graphql';
import { PirOverviewDetailsRedisFragment$key } from './__generated__/PirOverviewDetailsRedisFragment.graphql';
import { PirHistoryQuery$variables } from '../__generated__/PirHistoryQuery.graphql';

interface PirOverviewProps {
  dataHistory: PirOverviewHistoryFragment$key
  dataPir: NonNullable<PirQuery$data['pir']>
  dataRedis: PirOverviewDetailsRedisFragment$key
  historyPaginationOptions: PirHistoryQuery$variables
}

const PirOverview = ({
  dataHistory,
  dataPir,
  dataRedis,
  historyPaginationOptions,
}: PirOverviewProps) => {
  return (
    <Grid container spacing={3}>
      <Grid size={{ xs: 12 }} container direction='column' spacing={3}>
        <PirOverviewDetails data={dataPir} dataStream={dataRedis} />
        <PirOverviewCounts data={dataPir} />
      </Grid>
      <Grid size={{ xs: 6 }} container direction='column' spacing={3}>
        <PirOverviewHistory
          dataHistory={dataHistory}
          dataPir={dataPir}
          historyPaginationOptions={historyPaginationOptions}
        />
      </Grid>
      <Grid size={{ xs: 6 }} container direction='column' spacing={3}>
        <PirOverviewTopSources data={dataPir} />
        <PirOverviewCountFlagged data={dataPir} />
      </Grid>
    </Grid>
  );
};

export default PirOverview;
