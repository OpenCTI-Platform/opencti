import React, { CSSProperties } from 'react';
import Grid from '@mui/material/Grid2';
import { PirOverviewHistoryPirFragment$key } from '@components/pir/__generated__/PirOverviewHistoryPirFragment.graphql';
import StixRelationshipsDonut from '@components/common/stix_relationships/StixRelationshipsDonut';
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
      attribute: 'created-by.internal_id',
      isTo: false,
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
          <StixRelationshipsDonut
            dataSelection={topSourcesDataSelection}
            parameters={{ title: t_i18n('Top sources') }}
            variant="inLine"
            height={250}
            startDate={null}
            endDate={null}
            isReadOnly
          />
        </Paper>
      </Grid>
    </Grid>
  );
};

export default PirOverview;
