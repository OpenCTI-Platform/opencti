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
import { PirOverviewDetailsRedisFragment$key } from '@components/pir/pir_overview/__generated__/PirOverviewDetailsRedisFragment.graphql';
import { PirOverviewDetailsFragment$key } from './__generated__/PirOverviewDetailsFragment.graphql';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import ItemCreators from '../../../../components/ItemCreators';
import FilterIconButton from '../../../../components/FilterIconButton';
import { minutesBetweenDates, streamEventIdToDate } from '../../../../utils/Time';
import PirCriteriaDisplay from '../PirCriteriaDisplay';
import type { Theme } from '../../../../components/Theme';
import PaperAccordion from '../../../../components/PaperAccordion';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';

const detailsFragment = graphql`
  fragment PirOverviewDetailsFragment on Pir {
    description
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

const detailsRedisFragment = graphql`
  fragment PirOverviewDetailsRedisFragment on Query {
    redisStreamInfo {
      lastEventId
    }
  }
`;

interface PirOverviewDetailsProps {
  data: PirOverviewDetailsFragment$key
  dataStream: PirOverviewDetailsRedisFragment$key
}

const PirOverviewDetails = ({ data, dataStream }: PirOverviewDetailsProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();
  const pir = useFragment(detailsFragment, data);
  const { redisStreamInfo } = useFragment(detailsRedisFragment, dataStream);

  const lastEventDate = streamEventIdToDate(pir.lastEventId);
  const lastStreamEventDate = streamEventIdToDate(redisStreamInfo?.lastEventId);
  const diffInMinutes = minutesBetweenDates(lastEventDate, lastStreamEventDate);

  const criteria: FilterGroup[] = pir.pir_criteria.map((c) => JSON.parse(c.filters));

  return (
    <Grid size={{ xs: 12 }}>
      <PaperAccordion
        title={'PIR Details'}
        preview={(
          <div style={{
            flex: 1,
            display: 'flex',
            gap: theme.spacing(3),
            justifyContent: 'space-between',
            marginRight: theme.spacing(5),
          }}
          >
            <div>
              <Typography variant="h3" gutterBottom>
                {t_i18n('Rescan period (days)')}
              </Typography>
              <Typography variant="body2" gutterBottom>
                {pir.pir_rescan_days}
              </Typography>
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
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <Typography variant="h3" gutterBottom>
                {t_i18n('Last event processed')}
              </Typography>
              <Typography variant="body2" gutterBottom>
                {fldt(lastEventDate)}
              </Typography>
              {diffInMinutes > 1 && (
                <Typography variant="body2" gutterBottom sx={{ color: theme.palette.warn.main }}>
                  {t_i18n('Minutes behind stream', {
                    values: { minutes: diffInMinutes },
                  })}
                </Typography>
              )}
            </div>
            <div>
              <Typography variant="h3" gutterBottom>
                {t_i18n('Creation date')}
              </Typography>
              {fldt(pir.created_at)}
            </div>
          </div>
        )}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(3) }}>
          <div>
            <Typography variant="h3" gutterBottom>
              {t_i18n('Description')}
            </Typography>
            <ExpandableMarkdown source={pir.description} limit={400}/>
          </div>
          <div>
            <Typography variant="h3" gutterBottom>
              {t_i18n('Criteria')}
            </Typography>
            <PirCriteriaDisplay criteria={criteria} full />
          </div>
          <div>
            <Typography variant="h3" gutterBottom>
              {t_i18n('Creators')}
            </Typography>
            <ItemCreators creators={pir.creators ?? []}/>
          </div>
        </div>
      </PaperAccordion>
    </Grid>
  );
};

export default PirOverviewDetails;
