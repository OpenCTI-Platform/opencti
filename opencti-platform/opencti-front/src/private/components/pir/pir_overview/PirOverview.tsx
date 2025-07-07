import React, { CSSProperties } from 'react';
import Grid from '@mui/material/Grid2';
import PirOverviewCounts from './PirOverviewCounts';
import PirOverviewTopSources from './PirOverviewTopSources';
import PirOverviewDetails from './PirOverviewDetails';
import PirOverviewHistory from './PirOverviewHistory';
import Paper from '../../../../components/Paper';
import { useFormatter } from '../../../../components/i18n';
import { PirOverviewHistoryFragment$key } from './__generated__/PirOverviewHistoryFragment.graphql';
import { PirQuery$data } from '../__generated__/PirQuery.graphql';

interface PirOverviewProps {
  dataHistory: PirOverviewHistoryFragment$key
  dataPir: NonNullable<PirQuery$data['pir']>
}

const PirOverview = ({
  dataHistory,
  dataPir,
}: PirOverviewProps) => {
  const { t_i18n } = useFormatter();

  const verticalGridStyle: CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    gap: 2,
  };

  return (
    <Grid container spacing={3}>
      <Grid size={{ xs: 6 }} sx={verticalGridStyle}>
        <Paper title={t_i18n('PIR Details')}>
          <PirOverviewDetails data={dataPir} />
        </Paper>
      </Grid>
      <Grid size={{ xs: 6 }} sx={verticalGridStyle}>
        <PirOverviewCounts data={dataPir} />
        <Paper title={t_i18n('News feed')}>
          <PirOverviewHistory
            dataHistory={dataHistory}
            dataPir={dataPir}
          />
        </Paper>
      </Grid>
      <Grid size={{ xs: 6 }} sx={verticalGridStyle}>
        <PirOverviewTopSources data={dataPir} />
      </Grid>
    </Grid>
  );
};

export default PirOverview;
