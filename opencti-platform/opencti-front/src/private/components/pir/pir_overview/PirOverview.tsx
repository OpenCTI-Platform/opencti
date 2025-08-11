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
import { graphql, useFragment } from 'react-relay';
import PirThreatMap, { pirThreatMapQuery } from './PirThreatMap';
import PirOverviewCountFlagged from './PirOverviewCountFlagged';
import PirOverviewCounts from './PirOverviewCounts';
import PirOverviewTopSources from './PirOverviewTopSources';
import PirOverviewDetails from './PirOverviewDetails';
import PirOverviewHistory from './PirOverviewHistory';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { PirQuery$data } from '../__generated__/PirQuery.graphql';
import { PirOverviewHistoryFragment$key } from './__generated__/PirOverviewHistoryFragment.graphql';
import { PirThreatMapQuery } from './__generated__/PirThreatMapQuery.graphql';
import { PirOverviewFragment$key } from './__generated__/PirOverviewFragment.graphql';

const overviewFragment = graphql`
  fragment PirOverviewFragment on Pir {
    id
  }
`;

interface PirOverviewProps {
  dataHistory: PirOverviewHistoryFragment$key
  dataPir: NonNullable<PirQuery$data['pir']>
}

const PirOverview = ({
  dataHistory,
  dataPir,
}: PirOverviewProps) => {
  const { id } = useFragment<PirOverviewFragment$key>(overviewFragment, dataPir);
  const threatMapQueryRef = useQueryLoading<PirThreatMapQuery>(
    pirThreatMapQuery,
    {
      pirId: id,
      filters: {
        mode: 'and',
        filterGroups: [],
        filters: [{
          key: ['updated_at'],
          operator: 'within',
          values: ['now-2M', 'now'],
        }],
      },
    },
  );

  return (
    <Grid container spacing={3}>
      <Grid size={{ xs: 12 }} container direction='column' spacing={3}>
        <PirOverviewDetails data={dataPir} />
        <PirOverviewCounts data={dataPir} />
      </Grid>
      <Grid size={{ xs: 6 }} container direction='column' spacing={3}>
        <PirOverviewHistory
          dataHistory={dataHistory}
          dataPir={dataPir}
        />
        <PirOverviewCountFlagged data={dataPir} />
      </Grid>
      <Grid size={{ xs: 6 }} container direction='column' spacing={3}>
        {threatMapQueryRef && <PirThreatMap queryRef={threatMapQueryRef} />}
        <PirOverviewTopSources data={dataPir} />
      </Grid>
    </Grid>
  );
};

export default PirOverview;
