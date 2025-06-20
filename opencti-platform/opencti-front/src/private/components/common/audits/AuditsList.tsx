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

import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { AuditsListComponentQuery, LogsOrdering, OrderingMode } from './__generated__/AuditsListComponentQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { SETTINGS_SECURITYACTIVITY, SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../../../../utils/hooks/useGranted';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { buildFiltersAndOptionsForWidgets, sanitizeFilterGroupKeysForBackend } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import type { WidgetDataSelection, WidgetParameters } from '../../../../utils/widget/widget';
import WidgetListAudits from '../../../../components/dashboard/WidgetListAudits';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';

const auditsListComponentQuery = graphql`
  query AuditsListComponentQuery(
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
            workspace_type
          }
        }
      }
    }
  }
`;

interface AuditsListComponentProps {
  queryRef: PreloadedQuery<AuditsListComponentQuery>,
}

const AuditsListComponent: FunctionComponent<AuditsListComponentProps> = ({
  queryRef,
}) => {
  const queryData = usePreloadedQuery<AuditsListComponentQuery>(auditsListComponentQuery, queryRef);

  if (queryData && queryData.audits?.edges && queryData.audits.edges.length > 0) {
    const data = queryData.audits.edges;
    return (
      <WidgetListAudits data={data} />
    );
  }
  return <WidgetNoData />;
};

interface AuditsListProps {
  variant?: string,
  height?: number,
  startDate?: string | null,
  endDate?: string | null,
  dataSelection: WidgetDataSelection[],
  parameters?: WidgetParameters,
}

const AuditsList: FunctionComponent<AuditsListProps> = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  parameters,
}) => {
  const { t_i18n } = useFormatter();
  const isGrantedToSettings = useGranted([SETTINGS_SETACCESSES, SETTINGS_SECURITYACTIVITY, VIRTUAL_ORGANIZATION_ADMIN]);
  const isEnterpriseEdition = useEnterpriseEdition();

  const selection = dataSelection[0];
  const dateAttribute = (selection.date_attribute && selection.date_attribute.length > 0
    ? selection.date_attribute
    : 'timestamp') as LogsOrdering;
  const { filters } = buildFiltersAndOptionsForWidgets(
    selection.filters ?? undefined,
    { removeTypeAll: true, startDate: startDate ?? undefined, endDate: endDate ?? undefined, dateAttribute },
  );

  const queryRef = useQueryLoading<AuditsListComponentQuery>(auditsListComponentQuery, {
    types: ['History', 'Activity'],
    first: selection.number ?? 10,
    orderBy: dateAttribute,
    orderMode: (selection.sort_mode ?? 'desc') as OrderingMode,
    filters: filters ? sanitizeFilterGroupKeysForBackend(filters) : undefined,
  });

  return (
    <WidgetContainer
      height={height}
      title={parameters?.title ?? t_i18n('Audits list')}
      variant={variant}
    >
      {(!isGrantedToSettings || !isEnterpriseEdition)
        ? <div style={{ display: 'table', height: '100%', width: '100%' }}>
          <span
            style={{
              display: 'table-cell',
              verticalAlign: 'middle',
              textAlign: 'center',
            }}
          >
            {!isEnterpriseEdition
              ? t_i18n('This feature is only available in OpenCTI Enterprise Edition.')
              : t_i18n('You are not authorized to see this data.')}
          </span>
        </div>
        : <>
          {queryRef && (
            <React.Suspense fallback={<Loader variant={LoaderVariant.inElement}/>}>
              <AuditsListComponent queryRef={queryRef}/>
            </React.Suspense>
          )}
        </>}
    </WidgetContainer>
  );
};

export default AuditsList;
