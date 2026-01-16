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
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import { PirOverviewDetailsFragment$key } from './__generated__/PirOverviewDetailsFragment.graphql';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import ItemCreators from '../../../../components/ItemCreators';
import FilterIconButton from '../../../../components/FilterIconButton';
import { minutesBetweenDates, streamEventIdToDate, stringFormatMinutes } from '../../../../utils/Time';
import PirCriteriaDisplay from '../PirCriteriaDisplay';
import type { Theme } from '../../../../components/Theme';
import CardAccordion from '../../../../components/common/card/CardAccordion';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import Tag from '@common/tag/Tag';
import Label from '../../../../components/common/label/Label';

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
    queue_messages
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
  data: PirOverviewDetailsFragment$key;
  dataStream: PirOverviewDetailsRedisFragment$key;
}

const PirOverviewDetails = ({ data, dataStream }: PirOverviewDetailsProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt, n } = useFormatter();
  const pir = useFragment(detailsFragment, data);
  const { redisStreamInfo } = useFragment(detailsRedisFragment, dataStream);

  const lastEventDate = streamEventIdToDate(pir.lastEventId);
  const lastStreamEventDate = streamEventIdToDate(redisStreamInfo?.lastEventId);
  const diffInMinutes = minutesBetweenDates(lastEventDate, lastStreamEventDate);

  const criteria: FilterGroup[] = pir.pir_criteria.map((c) => JSON.parse(c.filters));

  return (
    <Grid size={{ xs: 12 }}>
      <CardAccordion
        title="PIR Details"
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
              <Label>{t_i18n('Rescan period (days)')}</Label>
              <Typography variant="body2" gutterBottom>
                {pir.pir_rescan_days}
              </Typography>
            </div>
            <div>
              <Label>{t_i18n('Filters')}</Label>
              <FilterIconButton
                key={pir.pir_filters}
                filters={JSON.parse(pir.pir_filters)}
                entityTypes={['Stix-Core-Object']}
                styleNumber={1}
              />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <Label>{t_i18n('Processing delay')}</Label>
              <Typography variant="body2" gutterBottom style={{ display: 'flex' }}>
                <span>
                  {diffInMinutes > 1 ? `${stringFormatMinutes(diffInMinutes, t_i18n)} ${t_i18n('behind live stream')}` : t_i18n('ON TIME')}
                </span>
                <Tooltip title={`${t_i18n('Last event processed')}: ${fldt(lastEventDate)}`}>
                  <InformationOutline
                    fontSize="small"
                    color="primary"
                    style={{ cursor: 'default', marginLeft: 8 }}
                  />
                </Tooltip>
              </Typography>
              <Tag label={`${n(pir.queue_messages)} ${t_i18n('messages in queue')}`} />
            </div>
            <div>
              <Label>{t_i18n('Creation date')}</Label>
              {fldt(pir.created_at)}
            </div>
            <div>
              <Label>{t_i18n('Creators')}</Label>
              <ItemCreators creators={pir.creators ?? []} />
            </div>
          </div>
        )}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(3) }}>
          <div>
            <Label>{t_i18n('Description')}</Label>
            <ExpandableMarkdown source={pir.description} limit={400} />
          </div>
          <div>
            <Label>{t_i18n('Criteria')}</Label>
            <PirCriteriaDisplay criteria={criteria} full />
          </div>
        </div>
      </CardAccordion>
    </Grid>
  );
};

export default PirOverviewDetails;
