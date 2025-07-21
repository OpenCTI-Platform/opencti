import { graphql, useFragment } from 'react-relay';
import React from 'react';
import Grid from '@mui/material/Grid2';
import StixRelationshipsMultiAreaChart from '@components/common/stix_relationships/StixRelationshipsMultiAreaChart';
import { PirOverviewCountFlaggedFragment$key } from './__generated__/PirOverviewCountFlaggedFragment.graphql';
import { useFormatter } from '../../../../components/i18n';
import Paper from '../../../../components/Paper';
import { monthsAgo } from '../../../../utils/Time';

const countFlaggedFragment = graphql`
  fragment PirOverviewCountFlaggedFragment on Pir {
    id
  }
`;

interface PirOverviewCountFlaggedProps {
  data: PirOverviewCountFlaggedFragment$key
}

const PirOverviewCountFlagged = ({ data }: PirOverviewCountFlaggedProps) => {
  const { t_i18n } = useFormatter();
  const { id } = useFragment(countFlaggedFragment, data);

  const dataSelection = [
    {
      field: 'created_at',
      filters: {
        mode: 'and',
        filters: [
          {
            key: 'relationship_type',
            values: ['in-pir'],
          },
          {
            key: 'toId',
            values: [id],
          },
        ],
        filterGroups: [],
      },
    },
  ];

  return (
    <Grid size={{ xs: 12 }}>
      <Paper title={t_i18n('Number of flagged entities')}>
        <StixRelationshipsMultiAreaChart
          relationshipTypes={['in-pir']}
          dataSelection={dataSelection}
          parameters={{ interval: 'month' }}
          variant="inLine"
          height={250}
          startDate={monthsAgo(6)}
          endDate={null}
          withoutTitle
          isReadOnly
        />
      </Paper>
    </Grid>
  );
};

export default PirOverviewCountFlagged;
