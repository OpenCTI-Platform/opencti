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
import { Box, Grid2 as Grid, Typography } from '@mui/material';
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

  const isOnTime = diffInMinutes <= 1;
  const processingLabel = isOnTime
    ? t_i18n('ON TIME')
    : `${stringFormatMinutes(diffInMinutes, t_i18n)} ${t_i18n('behind live stream')}`;

  return (
    <CardAccordion
      title={t_i18n('Configuration')}
      preview={(
        <Box
          data-testid="pir-configuration-summary"
          sx={{
            flex: 1,
            marginRight: theme.spacing(5),
            color: theme.palette.text.tertiary,
            fontSize: 13,
            lineHeight: '21px',
          }}
        >
          {t_i18n('Rescan period, filters, processing status and criteria')}
        </Box>
      )}
    >
      <Grid container spacing={3}>
        <Grid size={{ xs: 12, md: 6 }}>
          <Label>{t_i18n('Description')}</Label>
          <ExpandableMarkdown source={pir.description} limit={400} />
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <Label>{t_i18n('Criteria')}</Label>
          <PirCriteriaDisplay criteria={criteria} full />
        </Grid>
        <Grid size={{ xs: 6, md: 3 }}>
          <Label>{t_i18n('Rescan period (days)')}</Label>
          <Typography variant="body2">
            {pir.pir_rescan_days}
          </Typography>
        </Grid>
        <Grid size={{ xs: 6, md: 3 }}>
          <Label>{t_i18n('Creation date')}</Label>
          <Typography variant="body2">
            {fldt(pir.created_at)}
          </Typography>
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <Label>{t_i18n('Filters')}</Label>
          <FilterIconButton
            key={pir.pir_filters}
            filters={JSON.parse(pir.pir_filters)}
            entityTypes={['Stix-Core-Object']}
            variant="tag"
          />
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <Label
            action={(
              <Tooltip title={`${t_i18n('Last event processed')}: ${fldt(lastEventDate)}`}>
                <InformationOutline
                  fontSize="small"
                  color="primary"
                  style={{ cursor: 'default' }}
                />
              </Tooltip>
            )}
          >
            {t_i18n('Processing delay')}
          </Label>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="body2">
              {processingLabel}
            </Typography>
            <Tag label={`${n(pir.queue_messages)} ${t_i18n('messages in queue')}`} />
          </Box>
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <Label>{t_i18n('Creators')}</Label>
          <ItemCreators creators={pir.creators ?? []} />
        </Grid>
      </Grid>
    </CardAccordion>
  );
};

export default PirOverviewDetails;
