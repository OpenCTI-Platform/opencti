import React from 'react';
import { graphql, useFragment } from 'react-relay';
import StixRelationshipsDonut from '@components/common/stix_relationships/StixRelationshipsDonut';
import Paper from '../../../../components/Paper';
import { useFormatter } from '../../../../components/i18n';
import { PirOverviewTopSourcesFragment$key } from './__generated__/PirOverviewTopSourcesFragment.graphql';

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
            values: [id],
          },
        ],
        filterGroups: [],
      },
    },
  ];

  return (
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
  );
};

export default PirOverviewTopSources;
