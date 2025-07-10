import React from 'react';
import Grid from '@mui/material/Grid2';
import PirThreatMap from '@components/pir/pir_overview/PirThreatMap';
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

  return (
    <Grid container spacing={3}>
      <Grid size={{ xs: 6 }} container direction='column' spacing={3}>
        <Paper title={t_i18n('PIR Details')}>
          <PirOverviewDetails data={dataPir} />
        </Paper>
        <Paper title={t_i18n('Threat map')}>
          <PirThreatMap />
        </Paper>
        <Paper title={t_i18n('Top sources')}>
          <PirOverviewTopSources data={dataPir} />
        </Paper>
      </Grid>
      <Grid size={{ xs: 6 }} container direction='column' spacing={3}>
        <PirOverviewCounts data={dataPir} />
        <Paper title={t_i18n('News feed')}>
          <PirOverviewHistory
            dataHistory={dataHistory}
            dataPir={dataPir}
          />
        </Paper>
      </Grid>
    </Grid>
  );
};

export default PirOverview;
