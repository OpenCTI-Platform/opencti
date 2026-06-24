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
import type { ApexOptions } from 'apexcharts';
import ApexCharts from 'apexcharts';
import { useTheme } from '@mui/styles';
import { useNavigate } from 'react-router-dom';
import { AuditsHorizontalBarsDistributionQuery } from '@components/common/audits/__generated__/AuditsHorizontalBarsDistributionQuery.graphql';
import Chart from '../charts/Chart';
import { useFormatter } from '../../../../components/i18n';
import { horizontalBarsChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';
import useGranted, { SETTINGS_SECURITYACTIVITY, SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../../../../utils/hooks/useGranted';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useDistributionGraphData, { DistributionQueryData } from '../../../../utils/hooks/useDistributionGraphData';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import WidgetAccessDenied from '../../../../components/dashboard/WidgetAccessDenied';

const auditsHorizontalBarsDistributionQuery = graphql`
  query AuditsHorizontalBarsDistributionQuery(
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
      }
    }
  }
`;

interface AuditsHorizontalBarsComponentProps {
  queryRef: PreloadedQuery<AuditsHorizontalBarsDistributionQuery>;
  selection: WidgetDataSelection;
  distributed?: boolean;
  onMounted: (chart: ApexCharts) => void;
}

const AuditsHorizontalBarsComponent: FunctionComponent<AuditsHorizontalBarsComponentProps> = ({
  queryRef,
  selection,
  distributed,
  onMounted,
}) => {
  const theme = useTheme();
  const navigate = useNavigate();
  const { buildWidgetProps } = useDistributionGraphData();
  const data = usePreloadedQuery<AuditsHorizontalBarsDistributionQuery>(
    auditsHorizontalBarsDistributionQuery,
    queryRef,
  );

  if (data.auditsDistribution && data.auditsDistribution.length > 0) {
    const { series, redirectionUtils } = buildWidgetProps(
      data.auditsDistribution as unknown as DistributionQueryData,
      selection,
      'Number of history entries',
    );
    return (
      <Chart
        options={horizontalBarsChartOptions(
          theme,
          true,
          simpleNumberFormat,
          undefined,
          distributed,
          navigate,
          redirectionUtils,
        ) as ApexOptions}
        series={series}
        type="bar"
        width="100%"
        height="100%"
        onMounted={onMounted}
      />
    );
  }
  return <WidgetNoData />;
};

interface AuditsHorizontalBarsProps {
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

const AuditsHorizontalBars: FunctionComponent<AuditsHorizontalBarsProps> = ({
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
  const isGrantedToSettings = useGranted([SETTINGS_SETACCESSES, SETTINGS_SECURITYACTIVITY, VIRTUAL_ORGANIZATION_ADMIN]);
  const isEnterpriseEdition = useEnterpriseEdition();

  const buildQueryVariables = useCallback((resolvedDataSelection: WidgetDataSelection[]): AuditsHorizontalBarsDistributionQuery['variables'] => {
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

  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<AuditsHorizontalBarsDistributionQuery>({
    perspective: 'audits',
    dataSelection,
    host,
    refreshRate,
    query: auditsHorizontalBarsDistributionQuery,
    config,
    parameters,
    buildQueryVariables,
  });
  const selection = resolvedDataSelection[0];

  const renderContent = () => {
    if (isMissingHostEntity) {
      return <WidgetNoHostEntity host={host} />;
    }

    if (!isGrantedToSettings || !isEnterpriseEdition) {
      return <WidgetAccessDenied />;
    }

    if (!queryRef) {
      return <Loader variant={LoaderVariant.inElement} />;
    }

    return (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <AuditsHorizontalBarsComponent
          queryRef={queryRef}
          selection={selection}
          distributed={parameters.distributed ?? undefined}
          onMounted={setChart}
        />
      </Suspense>
    );
  };

  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title || t_i18n('Distribution of history')}
      variant={variant}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default AuditsHorizontalBars;
