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

import React, { CSSProperties, FunctionComponent, ReactNode, useCallback, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import ApexCharts from 'apexcharts';
import { AuditsTreeMapDistributionQuery } from '@components/common/audits/__generated__/AuditsTreeMapDistributionQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetTree from '../../../../components/dashboard/WidgetTree';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import AuditsWidgetRenderContent from '../../../../components/dashboard/AuditsWidgetRenderContent';

const auditsTreeMapDistributionQuery = graphql`
  query AuditsTreeMapDistributionQuery(
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
        ... on StixRelationship {
          representative {
            main
          }
        }
        # use colors when available
        ... on Label {
          color
        }
        ... on MarkingDefinition {
          x_opencti_color
        }
        # objects without representative
        ... on Creator {
          name
        }
        ... on Group {
          name
        }
        ... on Workspace {
          name
          type
        }
        ... on Status {
          template {
            name
            color
          }
        }
      }
    }
  }
`;

interface AuditsTreeMapComponentProps {
  queryRef: PreloadedQuery<AuditsTreeMapDistributionQuery>;
  selection: WidgetDataSelection;
  isDistributed?: boolean;
  onMounted: (chart: ApexCharts) => void;
}

const AuditsTreeMapComponent: FunctionComponent<AuditsTreeMapComponentProps> = ({
  queryRef,
  selection,
  isDistributed,
  onMounted,
}) => {
  const data = usePreloadedQuery<AuditsTreeMapDistributionQuery>(
    auditsTreeMapDistributionQuery,
    queryRef,
  );

  if (data.auditsDistribution && data.auditsDistribution.length > 0) {
    return (
      <WidgetTree
        data={data.auditsDistribution}
        groupBy={selection.attribute!}
        isDistributed={isDistributed}
        onMounted={onMounted}
      />
    );
  }
  return <WidgetNoData />;
};

interface AuditsTreeMapProps {
  variant?: string;
  height?: CSSProperties['height'];
  startDate?: string | null;
  endDate?: string | null;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  config: DashboardConfig;
  refreshRate?: number | null;
  popover?: ReactNode;
  host?: WidgetHost;
}

const AuditsTreeMap: FunctionComponent<AuditsTreeMapProps> = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
  config,
  refreshRate = null,
  popover,
  host,
}) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();

  const buildQueryVariables = useCallback((
    resolvedDataSelection: WidgetDataSelection[],
    _config: DashboardConfig,
    _parameters?: WidgetParameters,
  ): AuditsTreeMapDistributionQuery['variables'] => {
    const selection = resolvedDataSelection[0];
    const field = selection.attribute;
    return {
      types: ['History', 'Activity'],
      field: field!,
      operation: 'count' as const,
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

  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<AuditsTreeMapDistributionQuery>({
    perspective: 'audits',
    dataSelection,
    host,
    refreshRate,
    query: auditsTreeMapDistributionQuery,
    config,
    parameters,
    buildQueryVariables,
  });
  const selection = resolvedDataSelection[0];
  const isDistributed = parameters.distributed ?? undefined;

  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? t_i18n('Distribution of entities')}
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
        <AuditsTreeMapComponent
          queryRef={queryRef!}
          selection={selection}
          isDistributed={isDistributed}
          onMounted={setChart}
        />
      </AuditsWidgetRenderContent>
    </WidgetContainer>
  );
};

export default AuditsTreeMap;
