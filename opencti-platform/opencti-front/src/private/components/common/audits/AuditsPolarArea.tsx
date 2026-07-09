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

import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { CSSProperties, ReactNode, useCallback, useState } from 'react';
import ApexCharts from 'apexcharts';
import { AuditsPolarAreaDistributionQuery } from '@components/common/audits/__generated__/AuditsPolarAreaDistributionQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetPolarArea from '../../../../components/dashboard/WidgetPolarArea';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { OpenCTIChartProps } from '../charts/Chart';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import AuditsWidgetRenderContent from '../../../../components/dashboard/AuditsWidgetRenderContent';

const auditsPolarAreaDistributionQuery = graphql`
  query AuditsPolarAreaDistributionQuery(
    $field: String!
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $operation: StatsOperation!
    $limit: Int
    $order: String
    $types: [String]
    $filters: FilterGroup
    $search: String
  ) {
    auditsDistribution(
      field: $field
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      operation: $operation
      limit: $limit
      order: $order
      types: $types
      filters: $filters
      search: $search
    ) {
      label
      value
      entity {
        ... on BasicObject {
          id
          entity_type
        }
        ... on BasicRelationship {
          id
          entity_type
        }
        ... on StixObject {
          representative {
            main
          }
        }
        # objects without representative
        ... on Creator {
          name
        }
        ... on Group {
          name
        }
      }
    }
  }
`;

interface AuditsPolarAreaComponentProps {
  dataSelection: WidgetDataSelection[];
  queryRef: PreloadedQuery<AuditsPolarAreaDistributionQuery>;
  onMounted?: OpenCTIChartProps['onMounted'];
}

const AuditsPolarAreaComponent = ({
  dataSelection,
  queryRef,
  onMounted,
}: AuditsPolarAreaComponentProps) => {
  const { auditsDistribution } = usePreloadedQuery(
    auditsPolarAreaDistributionQuery,
    queryRef,
  );

  if (
    auditsDistribution
    && auditsDistribution.length > 0
  ) {
    const attributeField = dataSelection[0].attribute || 'entity_type';
    return (
      <WidgetPolarArea
        data={[...auditsDistribution]}
        groupBy={attributeField}
        onMounted={onMounted}
      />
    );
  }
  return <WidgetNoData />;
};

interface AuditsPolarAreaProps {
  startDate?: string | null;
  endDate?: string | null;
  dataSelection: WidgetDataSelection[];
  parameters: WidgetParameters;
  config: DashboardConfig;
  refreshRate?: number | null;
  variant?: string;
  height?: CSSProperties['height'];
  popover?: ReactNode;
  host?: WidgetHost;
}

const AuditsPolarArea = ({
  startDate,
  endDate,
  dataSelection,
  parameters,
  config,
  refreshRate = null,
  height,
  variant,
  popover,
  host,
}: AuditsPolarAreaProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();

  const buildQueryVariables = useCallback((resolvedSelection: WidgetDataSelection[]): AuditsPolarAreaDistributionQuery['variables'] => {
    const selection = resolvedSelection[0];
    return {
      types: ['History', 'Activity'],
      field: (selection.attribute || 'entity_type') as string,
      operation: 'count',
      startDate: startDate ?? undefined,
      endDate: endDate ?? undefined,
      dateAttribute:
        selection.date_attribute && selection.date_attribute.length > 0
          ? selection.date_attribute
          : 'timestamp',
      filters: normalizeFilterGroupForBackend(selection.filters),
      limit: selection.number ?? 10,
    };
  }, [startDate, endDate]);

  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<AuditsPolarAreaDistributionQuery>({
    perspective: 'audits',
    dataSelection,
    host,
    refreshRate,
    query: auditsPolarAreaDistributionQuery,
    config,
    parameters,
    buildQueryVariables,
  });

  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? t_i18n('Distribution of history')}
      variant={variant}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <AuditsWidgetRenderContent
        isMissingHostEntity={isMissingHostEntity}
        isMissingSavedFilters={isMissingSavedFilters}
        queryRef={queryRef}
        host={host}
      >
        <AuditsPolarAreaComponent
          queryRef={queryRef!}
          dataSelection={resolvedDataSelection}
          onMounted={setChart}
        />
      </AuditsWidgetRenderContent>
    </WidgetContainer>
  );
};

export default AuditsPolarArea;
