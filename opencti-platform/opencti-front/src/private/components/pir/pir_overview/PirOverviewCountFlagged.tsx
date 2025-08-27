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

import { graphql, useFragment } from 'react-relay';
import React from 'react';
import Grid from '@mui/material/Grid2';
import { PirOverviewCountFlaggedFragment$key } from './__generated__/PirOverviewCountFlaggedFragment.graphql';
import { useFormatter } from '../../../../components/i18n';
import Paper from '../../../../components/Paper';
import { monthsAgo } from '../../../../utils/Time';
import PirRelationshipsMultiAreaChart from '../PirRelationshipsMultiAreaChart';

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
      pirId: id,
    },
  ];

  return (
    <Grid size={{ xs: 12 }}>
      <Paper title={t_i18n('Number of threats over time')}>
        <PirRelationshipsMultiAreaChart
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
