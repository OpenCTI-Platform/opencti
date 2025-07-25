import React from 'react';
import Grid from '@mui/material/Grid2';
import { graphql, useFragment } from 'react-relay';
import StixRelationshipsDonut from '@components/common/stix_relationships/StixRelationshipsDonut';
import StixCoreObjectsDonut from '@components/common/stix_core_objects/StixCoreObjectsDonut';
import { PirOverviewTopSourcesFragment$key } from './__generated__/PirOverviewTopSourcesFragment.graphql';
import Paper from '../../../../components/Paper';
import { useFormatter } from '../../../../components/i18n';

const topSourcesFragment = graphql`
  fragment PirOverviewTopSourcesFragment on Pir {
    id
  }
`;

interface PirOverviewTopSourcesProps {
  data: PirOverviewTopSourcesFragment$key
}

const PirOverviewTopSources = ({ data }: PirOverviewTopSourcesProps) => {
  const { t_i18n } = useFormatter();
  const { id } = useFragment(topSourcesFragment, data);

  const flaggedEntitiesTopSourcesDataSelection = [
    {
      attribute: 'created-by.internal_id',
      isTo: false,
      filters: {
        mode: 'and',
        filters: [
          {
            key: 'regardingOf',
            values: [
              { key: 'relationship_type', values: ['in-pir'] },
              { key: 'id', values: [id] },
            ],
          },
        ],
        filterGroups: [],
      },
    },
  ];

  const relationshipsTopSourcesDataSelection = [ // TODO PIR not working
    {
      attribute: 'created-by.internal_id', // TODO set dependencies
      isTo: false,
      relationship_type: 'in-pir',
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
    <Grid container spacing={3}>
      <Paper title={t_i18n('Top sources of flagged entities')}>
        <StixCoreObjectsDonut
          dataSelection={flaggedEntitiesTopSourcesDataSelection}
          variant="inLine"
          height={250}
          startDate={null}
          endDate={null}
          isReadOnly
          withoutTitle
        />
      </Paper>
      <Paper title={t_i18n('Top sources of the relationships causing the flags')}>
        <StixRelationshipsDonut
          dataSelection={relationshipsTopSourcesDataSelection}
          variant="inLine"
          height={250}
          startDate={null}
          endDate={null}
          isReadOnly
          withoutTitle
        />
      </Paper>
    </Grid>
  );
};

export default PirOverviewTopSources;
