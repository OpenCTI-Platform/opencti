import React, { CSSProperties } from 'react';
import Grid from '@mui/material/Grid2';
import PirOverviewDetails from './PirOverviewDetails';
import PirOverviewHistory from './PirOverviewHistory';
import Paper from '../../../components/Paper';
import { useFormatter } from '../../../components/i18n';
import { PirOverviewHistoryFragment$key } from './__generated__/PirOverviewHistoryFragment.graphql';
import { PirOverviewDetailsFragment$key } from './__generated__/PirOverviewDetailsFragment.graphql';
import { PirOverviewHistoryPirFragment$key } from './__generated__/PirOverviewHistoryPirFragment.graphql';

interface PirOverviewProps {
  dataHistory: PirOverviewHistoryFragment$key
  dataDetails: PirOverviewDetailsFragment$key
  dataHistoryPir: PirOverviewHistoryPirFragment$key
}

const PirOverview = ({
  dataHistory,
  dataDetails,
  dataHistoryPir,
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
          <PirOverviewDetails data={dataDetails} />
        </Paper>
      </Grid>
      <Grid size={{ xs: 6 }} sx={verticalGridStyle}>
        <Paper title={t_i18n('News feed')}>
          <PirOverviewHistory
            dataHistory={dataHistory}
            dataPir={dataHistoryPir}
          />
        </Paper>
      </Grid>
    </Grid>
  );
};

export default PirOverview;
