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
      <Grid size={{ xs: 6 }} container direction='column' spacing={3}>
        <PirOverviewCounts data={dataPir} />
        {threatMapQueryRef && <PirThreatMap queryRef={threatMapQueryRef} />}
        <PirOverviewTopSources data={dataPir} />
        <PirOverviewCountFlagged data={dataPir} />
        <PirOverviewDetails data={dataPir} />
      </Grid>
      <Grid size={{ xs: 6 }} container direction='column' spacing={3}>
        <PirOverviewHistory
          dataHistory={dataHistory}
          dataPir={dataPir}
        />
      </Grid>
    </Grid>
  );
};

export default PirOverview;
