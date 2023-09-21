/*
Copyright (c) 2021-2023 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React from 'react';
import { graphql } from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import * as R from 'ramda';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { convertFilters } from '../../../../utils/ListParameters';
import ItemNumberDifference from '../../../../components/ItemNumberDifference';
import { dayAgo } from '../../../../utils/Time';
import useGranted, { SETTINGS } from '../../../../utils/hooks/useGranted';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

const useStyles = makeStyles((theme) => ({
  paper: {
    minHeight: 280,
    height: '100%',
    margin: '4px 0 0 0',
    padding: '0 0 10px 0',
    borderRadius: 6,
  },
  chip: {
    fontSize: 10,
    height: 20,
    marginLeft: 10,
  },
  number: {
    float: 'left',
    fontSize: 40,
  },
  title: {
    marginTop: 5,
    textTransform: 'uppercase',
    fontSize: 12,
    fontWeight: 500,
    color: theme.palette.text.secondary,
  },
  icon: {
    position: 'absolute',
    color: theme.palette.primary.main,
    top: 30,
    right: 20,
  },
}));

const auditsNumberNumberQuery = graphql`
  query AuditsNumberNumberSeriesQuery(
    $types: [String]
    $startDate: DateTime
    $endDate: DateTime
    $onlyInferred: Boolean
    $filters: [LogsFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    auditsNumber(
      types: $types
      startDate: $startDate
      endDate: $endDate
      onlyInferred: $onlyInferred
      filters: $filters
      filterMode: $filterMode
      search: $search
    ) {
      total
      count
    }
  }
`;

const AuditsNumber = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
}) => {
  const classes = useStyles();
  const { t, n } = useFormatter();
  const isGrantedToSettings = useGranted([SETTINGS]);
  const isEnterpriseEdition = useEnterpriseEdition();
  const renderContent = () => {
    if (!isGrantedToSettings || !isEnterpriseEdition) {
      return (
        <div style={{ display: 'table', height: '100%', width: '100%' }}>
          <span
            style={{
              display: 'table-cell',
              verticalAlign: 'middle',
              textAlign: 'center',
            }}
          >
            {!isEnterpriseEdition
              ? t(
                'This feature is only available in OpenCTI Enterprise Edition.',
              )
              : t('You are not authorized to see this data.')}
          </span>
        </div>
      );
    }
    const selection = dataSelection[0];
    let types = ['History', 'Activity'];
    if (
      selection.filters.entity_type
      && selection.filters.entity_type.length > 0
    ) {
      if (
        selection.filters.entity_type.filter((o) => o.id === 'all').length === 0
      ) {
        types = selection.filters.entity_type.map((o) => o.id);
      }
    }
    const filters = convertFilters(R.dissoc('entity_type', selection.filters));
    const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
      ? selection.date_attribute
      : 'timestamp';
    if (startDate) {
      filters.push({ key: dateAttribute, values: [startDate], operator: 'gt' });
    }
    if (endDate) {
      filters.push({ key: dateAttribute, values: [endDate], operator: 'lt' });
    }
    return (
      <QueryRenderer
        query={auditsNumberNumberQuery}
        variables={{ types, filters, startDate, endDate: dayAgo() }}
        render={({ props }) => {
          if (props && props.auditsNumber) {
            const { total } = props.auditsNumber;
            const difference = total - props.auditsNumber.count;
            return (
              <div>
                <div className={classes.number}>{n(total)}</div>
                <ItemNumberDifference
                  difference={difference}
                  description={t('24 hours')}
                />
              </div>
            );
          }
          if (props) {
            return (
              <div style={{ display: 'table', height: '100%', width: '100%' }}>
                <span
                  style={{
                    display: 'table-cell',
                    verticalAlign: 'middle',
                    textAlign: 'center',
                  }}
                >
                  {t('No entities of this type has been found.')}
                </span>
              </div>
            );
          }
          return (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                <CircularProgress size={40} thickness={2} />
              </span>
            </div>
          );
        }}
      />
    );
  };
  return (
    <div style={{ height: height || '100%' }}>
      <Typography
        variant="h4"
        gutterBottom={true}
        style={{
          margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 10px -7px',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        {parameters.title ?? t('Entities number')}
      </Typography>
      {variant !== 'inLine' ? (
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {renderContent()}
        </Paper>
      ) : (
        renderContent()
      )}
    </div>
  );
};

export default AuditsNumber;
