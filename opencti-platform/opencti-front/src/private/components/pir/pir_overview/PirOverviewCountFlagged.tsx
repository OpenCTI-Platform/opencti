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
import Grid from '@mui/material/Grid2';
import { PirOverviewCountFlaggedFragment$key } from './__generated__/PirOverviewCountFlaggedFragment.graphql';
import { useFormatter } from '../../../../components/i18n';
import PirRelationshipsMultiAreaChart from '../PirRelationshipsMultiAreaChart';
import Card from '../../../../components/common/card/Card';

const countFlaggedFragment = graphql`
  fragment PirOverviewCountFlaggedFragment on Pir {
    id
  }
`;

interface PirOverviewCountFlaggedProps {
  data: PirOverviewCountFlaggedFragment$key;
}

const PirOverviewCountFlagged = ({ data }: PirOverviewCountFlaggedProps) => {
  const { t_i18n } = useFormatter();
  const { id } = useFragment(countFlaggedFragment, data);

  return (
    <Grid size={{ xs: 12 }}>
      <Card
        padding="small"
        title={t_i18n('Number of threats over time')}
      >
        <PirRelationshipsMultiAreaChart pirId={id} />
      </Card>
    </Grid>
  );
};

export default PirOverviewCountFlagged;
