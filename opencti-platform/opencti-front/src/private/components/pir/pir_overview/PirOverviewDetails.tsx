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
import { graphql, useFragment } from 'react-relay';
import { Grid2 as Grid, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import Chip from '@mui/material/Chip';
import { PirOverviewDetailsFragment$key } from './__generated__/PirOverviewDetailsFragment.graphql';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import ItemCreators from '../../../../components/ItemCreators';
import FilterIconButton from '../../../../components/FilterIconButton';
import { parse } from '../../../../utils/Time';
import PirFiltersDisplay from '../PirFiltersDisplay';
import type { Theme } from '../../../../components/Theme';
import Paper from '../../../../components/Paper';

const detailsFragment = graphql`
  fragment PirOverviewDetailsFragment on Pir {
    description
    pir_type
    pir_rescan_days
    created_at
    lastEventId
    creators {
      id
      name
    }
    pir_filters
    pir_criteria {
      filters
    }
  }
`;

interface PirOverviewDetailsProps {
  data: PirOverviewDetailsFragment$key
}

const PirOverviewDetails = ({ data }: PirOverviewDetailsProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();
  const pir = useFragment(detailsFragment, data);

  const lastEventDate = parse(parseInt((pir.lastEventId || '-').split('-')[0], 10));

  return (
    <Grid size={{ xs: 12 }}>
      <Paper title={t_i18n('PIR Details')}>
        <Grid container spacing={2}>
          <Grid
            size={{ xs: 6 }}
            sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}
          >
            <div>
              <Typography variant="h3" gutterBottom>
                {t_i18n('Description')}
              </Typography>
              <ExpandableMarkdown source={pir.description} limit={400}/>
            </div>

            <div>
              <Typography variant="h3" gutterBottom>
                {t_i18n('Creation date')}
              </Typography>
              {fldt(pir.created_at)}
            </div>

            <div>
              <Typography variant="h3" gutterBottom>
                {t_i18n('Filters')}
              </Typography>
              <FilterIconButton
                key={pir.pir_filters}
                filters={JSON.parse(pir.pir_filters)}
                entityTypes={['Stix-Core-Object']}
                styleNumber={1}
              />
            </div>

            <div>
              <Typography variant="h3" gutterBottom>
                {t_i18n('Criteria')}
              </Typography>
              <div style={{ display: 'flex', gap: theme.spacing(1), flexFlow: 'row wrap' }}>
                {pir.pir_criteria.map((c, i) => (
                  <PirFiltersDisplay
                    key={i}
                    filterGroup={JSON.parse(c.filters)}
                  />
                ))}
              </div>
            </div>
          </Grid>

          <Grid
            size={{ xs: 6 }}
            sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}
          >
            <div>
              <Typography variant="h3" gutterBottom>
                {t_i18n('Type')}
              </Typography>
              <Chip
                style={{
                  textTransform: 'uppercase',
                  borderRadius: 4,
                }}
                color="primary"
                variant="outlined"
                label={t_i18n(pir.pir_type)}
              />
            </div>

            <div>
              <Typography variant="h3" gutterBottom>
                {t_i18n('Rescan period (days)')}
              </Typography>
              {pir.pir_rescan_days}
            </div>

            <div>
              <Typography variant="h3" gutterBottom>
                {t_i18n('Last event processed')}
              </Typography>
              {fldt(lastEventDate)}
            </div>

            <div>
              <Typography variant="h3" gutterBottom>
                {t_i18n('Creators')}
              </Typography>
              <ItemCreators creators={pir.creators ?? []}/>
            </div>
          </Grid>
        </Grid>
      </Paper>
    </Grid>
  );
};

export default PirOverviewDetails;
