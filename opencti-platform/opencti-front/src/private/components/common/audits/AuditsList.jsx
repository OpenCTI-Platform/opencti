/*
Copyright (c) 2021-2024 Filigran SAS

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
import ListItem from '@mui/material/ListItem';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import List from '@mui/material/List';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { resolveLink } from '../../../../utils/Entity';
import useGranted, { SETTINGS } from '../../../../utils/hooks/useGranted';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import { isNotEmptyField } from '../../../../utils/utils';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetLoader from '../../../../components/dashboard/WidgetLoader';

const useStyles = makeStyles({
  container: {
    width: '100%',
    height: '100%',
    overflow: 'auto',
    paddingBottom: 10,
    marginBottom: 10,
  },
  paper: {
    height: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 4,
  },
  item: {
    height: 50,
    minHeight: 50,
    maxHeight: 50,
    paddingRight: 0,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
});

const auditsListQuery = graphql`
  query AuditsListQuery(
    $types: [String!]
    $first: Int
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    audits(
      types: $types
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) {
      edges {
        node {
          id
          entity_type
          event_status
          event_type
          event_scope
          timestamp
          user {
            id
            entity_type
            name
          }
          context_data {
            entity_id
            entity_type
            entity_name
            message
          }
        }
      }
    }
  }
`;

const AuditsList = ({
  variant = null,
  height,
  startDate = null,
  endDate = null,
  dataSelection,
  parameters = {},
}) => {
  const classes = useStyles();
  const theme = useTheme();
  const { t_i18n, fldt } = useFormatter();
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
              ? t_i18n(
                'This feature is only available in OpenCTI Enterprise Edition.',
              )
              : t_i18n('You are not authorized to see this data.')}
          </span>
        </div>
      );
    }
    const selection = dataSelection[0];
    const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
      ? selection.date_attribute
      : 'timestamp';
    const { filters } = buildFiltersAndOptionsForWidgets(selection.filters, { removeTypeAll: true, startDate, endDate, dateAttribute });
    return (
      <QueryRenderer
        query={auditsListQuery}
        variables={{
          types: ['History', 'Activity'],
          first: selection.number ?? 10,
          orderBy: dateAttribute,
          orderMode: 'desc',
          filters,
        }}
        render={({ props }) => {
          if (props && props.audits && props.audits.edges.length > 0) {
            const data = props.audits.edges;
            return (
              <div id="container" className={classes.container}>
                <List style={{ marginTop: -10 }}>
                  {data.map((auditEdge) => {
                    const audit = auditEdge.node;
                    const color = audit.event_status === 'error'
                      ? theme.palette.error.main
                      : undefined;
                    const isHistoryUpdate = data.entity_type === 'History'
                      && data.event_type === 'update'
                      && isNotEmptyField(audit.context_data?.entity_name);
                    const message = `\`${audit.user?.name}\` ${
                      audit.context_data?.message
                    } ${
                      isHistoryUpdate
                        ? `for \`${audit.context_data?.entity_name}\` (${audit.context_data?.entity_type})`
                        : ''
                    }`;
                    const link = audit.context_data?.entity_type
                      ? `${resolveLink(
                        audit.context_data?.entity_type === 'Workspace'
                          ? audit.context_data?.workspace_type
                          : audit.context_data?.entity_type,
                      )}/${audit.context_data?.entity_id}`
                      : undefined;
                    return (
                      <ListItem
                        key={audit.id}
                        dense={true}
                        button={true}
                        className="noDrag"
                        classes={{ root: classes.item }}
                        divider={true}
                        component={link ? Link : undefined}
                        to={link}
                      >
                        <ListItemIcon>
                          <ItemIcon
                            color={color}
                            type={
                              audit.context_data?.entity_type
                              ?? audit.event_type
                            }
                          />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <>
                              <div
                                className={classes.bodyItem}
                                style={{ width: '15%' }}
                              >
                                <span style={{ color }}>
                                  {fldt(audit.timestamp)}
                                </span>
                              </div>
                              <div
                                className={classes.bodyItem}
                                style={{ width: '18%' }}
                              >
                                {audit.user?.name ?? '-'}
                              </div>
                              <div
                                className={classes.bodyItem}
                                style={{ width: '15%' }}
                              >
                                {audit.event_scope}
                              </div>
                              <div
                                className={classes.bodyItem}
                                style={{ width: '22%' }}
                              >
                                {audit.context_data?.entity_name
                                  ?? audit.event_type}
                              </div>
                              <div
                                className={classes.bodyItem}
                                style={{ width: '30%' }}
                              >
                                <span style={{ color }}>
                                  <MarkdownDisplay
                                    content={message}
                                    remarkGfmPlugin={true}
                                    commonmark={true}
                                  />
                                </span>
                              </div>
                            </>
                          }
                        />
                      </ListItem>
                    );
                  })}
                </List>
              </div>
            );
          }
          if (props) {
            return <WidgetNoData />;
          }
          return <WidgetLoader />;
        }}
      />
    );
  };
  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? title ?? t_i18n('Audits list')}
      variant={variant}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default AuditsList;
