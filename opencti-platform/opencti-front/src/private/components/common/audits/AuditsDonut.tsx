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

import React, { CSSProperties, FunctionComponent, ReactNode, Suspense, useCallback, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import ApexCharts from 'apexcharts';
import { AuditsDonutDistributionQuery } from '@components/common/audits/__generated__/AuditsDonutDistributionQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { SETTINGS_SECURITYACTIVITY, SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../../../../utils/hooks/useGranted';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetDonut from '../../../../components/dashboard/WidgetDonut';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import WidgetNoSavedFilters from 'src/components/dashboard/WidgetNoSavedFilters';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import WidgetAccessDenied from '../../../../components/dashboard/WidgetAccessDenied';

const auditsDonutDistributionQuery = graphql`
  query AuditsDonutDistributionQuery(
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

interface AuditsDonutComponentProps {
  queryRef: PreloadedQuery<AuditsDonutDistributionQuery>;
  selection: WidgetDataSelection;
  onMounted: (chart: ApexCharts) => void;
}

const AuditsDonutComponent: FunctionComponent<AuditsDonutComponentProps> = ({
  queryRef,
  selection,
  onMounted,
}) => {
  const data = usePreloadedQuery<AuditsDonutDistributionQuery>(
    auditsDonutDistributionQuery,
    queryRef,
  );

  if (data.auditsDistribution && data.auditsDistribution.length > 0) {
    return (
      <WidgetDonut
        data={data.auditsDistribution}
        groupBy={selection.attribute!}
        onMounted={onMounted}
      />
    );
  }
  return <WidgetNoData />;
};

interface AuditsDonutProps {
  variant?: string;
  height?: CSSProperties['height'];
  startDate?: string | null;
  endDate?: string | null;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const AuditsDonut: FunctionComponent<AuditsDonutProps> = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
  popover,
  host,
  config,
  refreshRate = null,
}) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const isGrantedToSettings = useGranted([SETTINGS_SETACCESSES, SETTINGS_SECURITYACTIVITY, VIRTUAL_ORGANIZATION_ADMIN]);
  const isEnterpriseEdition = useEnterpriseEdition();

  const buildQueryVariables = useCallback((resolvedDataSelection: WidgetDataSelection[]): AuditsDonutDistributionQuery['variables'] => {
    const selection = resolvedDataSelection[0];
    return {
      types: ['History', 'Activity'],
      field: selection.attribute as string,
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

  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<AuditsDonutDistributionQuery>({
    perspective: 'audits',
    dataSelection,
    host,
    refreshRate,
    query: auditsDonutDistributionQuery,
    config,
    parameters,
    buildQueryVariables,
  });
  const selection = resolvedDataSelection[0];

  const renderContent = () => {
    if (isMissingHostEntity) {
      return <WidgetNoHostEntity host={host} />;
    }

    if (isMissingSavedFilters) {
      return <WidgetNoSavedFilters />;
    }

    if (!isGrantedToSettings || !isEnterpriseEdition) {
      return <WidgetAccessDenied />;
    }

    if (!queryRef) {
      return <Loader variant={LoaderVariant.inElement} />;
    }

    return (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <AuditsDonutComponent
          queryRef={queryRef}
          selection={selection}
          onMounted={setChart}
        />
      </Suspense>
    );
  };

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
      {renderContent()}
    </WidgetContainer>
  );
};

export default AuditsDonut;
