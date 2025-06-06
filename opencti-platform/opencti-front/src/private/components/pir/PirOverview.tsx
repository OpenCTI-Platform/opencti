import React, { CSSProperties } from 'react';
import Grid from '@mui/material/Grid2';
import StixCoreObjectsDonut from '@components/common/stix_core_objects/StixCoreObjectsDonut';
import { PirOverviewHistoryPirFragment$key } from '@components/pir/__generated__/PirOverviewHistoryPirFragment.graphql';
import PirOverviewDetails from './PirOverviewDetails';
import PirOverviewHistory from './PirOverviewHistory';
import Paper from '../../../components/Paper';
import { useFormatter } from '../../../components/i18n';
import { PirOverviewHistoryFragment$key } from './__generated__/PirOverviewHistoryFragment.graphql';
import { PirOverviewDetailsFragment$key } from './__generated__/PirOverviewDetailsFragment.graphql';

interface PirOverviewProps {
  pirId: string
  dataHistory: PirOverviewHistoryFragment$key
  dataDetails: PirOverviewDetailsFragment$key
  dataHistoryPir: PirOverviewHistoryPirFragment$key
}

const PirOverview = ({
  pirId,
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

  const topSourcesDataSelection = [
    {
      attribute: 'pir_dependencies.author_id',
      filters: {
        mode: 'and',
        filters: [
          {
            key: 'relationship_type',
            values: ['in-pir'],
          },
          {
            key: 'toId',
            values: [pirId],
          },
        ],
        filterGroups: [],
      },
    },
  ];

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
      <Grid size={{ xs: 6 }} sx={verticalGridStyle}>
        <Paper title={t_i18n('PIR Visualization')}>
          <StixCoreObjectsDonut
            dataSelection={topSourcesDataSelection}
            parameters={{ title: t_i18n('Top sources') }}
            variant="inEntity"
            height={250}
            startDate={undefined}
            endDate={undefined}
          />
        </Paper>
      </Grid>
    </Grid>
  );
};

export default PirOverview;
