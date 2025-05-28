import React from 'react';
import Grid from '@mui/material/Grid2';
import PirOverviewDetails from '@components/pir/PirOverviewDetails';
import PirOverviewHistory from '@components/pir/PirOverviewHistory';
import { PirOverviewHistoryFragment$key } from './__generated__/PirOverviewHistoryFragment.graphql';
import { useFormatter } from '../../../components/i18n';
import Paper from '../../../components/Paper';
import { PirOverviewDetailsFragment$key } from './__generated__/PirOverviewDetailsFragment.graphql';

interface PirOverviewProps {
  dataHistory: PirOverviewHistoryFragment$key
  dataDetails: PirOverviewDetailsFragment$key
}

const PirOverview = ({ dataHistory, dataDetails }: PirOverviewProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Grid container spacing={3}>
      <Grid size={{ sm: 6 }}>
        <Paper title={t_i18n('PIR Details')}>
          <PirOverviewDetails data={dataDetails} />
        </Paper>
      </Grid>
      <Grid size={{ sm: 6 }}>
        <Paper
          title={t_i18n('Recent history')}
          variant="outlined"
        >
          <PirOverviewHistory data={dataHistory} />
        </Paper>
      </Grid>
    </Grid>
  );
};

export default PirOverview;
