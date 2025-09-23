/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React from 'react';
import Grid from '@mui/material/Grid2';
import { graphql, useFragment } from 'react-relay';
import StixCoreObjectsDonut from '@components/common/stix_core_objects/StixCoreObjectsDonut';
import PirRelationshipsDonut from '@components/pir/PirRelationshipsDonut';
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

  const relationshipsTopSourcesDataSelection = [
    {
      attribute: 'pir_explanation.dependencies.author_id',
      isTo: false,
      relationship_type: 'in-pir',
      pirId: id,
    },
  ];

  return (
    <Grid container spacing={3}>
      <Grid size={{ xs: 6 }}>
        <Paper title={t_i18n('Top authors of threat entities')}>
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
      </Grid>
      <Grid size={{ xs: 6 }}>
        <Paper title={t_i18n('Top authors of relationships from threats')}>
          <PirRelationshipsDonut
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
    </Grid>
  );
};

export default PirOverviewTopSources;
