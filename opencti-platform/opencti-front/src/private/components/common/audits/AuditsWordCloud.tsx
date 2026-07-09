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

import React, { CSSProperties, FunctionComponent, ReactNode, Suspense, useCallback } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { AuditsWordCloudDistributionQuery } from '@components/common/audits/__generated__/AuditsWordCloudDistributionQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { SETTINGS_SECURITYACTIVITY, SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../../../../utils/hooks/useGranted';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetWordCloud from '../../../../components/dashboard/WidgetWordCloud';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import WidgetNoSavedFilters from 'src/components/dashboard/WidgetNoSavedFilters';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import WidgetAccessDenied from '../../../../components/dashboard/WidgetAccessDenied';

const auditsWordCloudDistributionQuery = graphql`
  query AuditsWordCloudDistributionQuery(
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

interface AuditsWordCloudComponentProps {
  queryRef: PreloadedQuery<AuditsWordCloudDistributionQuery>;
  selection: WidgetDataSelection;
}

const AuditsWordCloudComponent: FunctionComponent<AuditsWordCloudComponentProps> = ({
  queryRef,
  selection,
}) => {
  const data = usePreloadedQuery<AuditsWordCloudDistributionQuery>(
    auditsWordCloudDistributionQuery,
    queryRef,
  );

  if (data.auditsDistribution && data.auditsDistribution.length > 0) {
    return (
      <WidgetWordCloud
        data={data.auditsDistribution}
        groupBy={selection.attribute!}
      />
    );
  }
  return <WidgetNoData />;
};

interface AuditsWordCloudProps {
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

const AuditsWordCloud: FunctionComponent<AuditsWordCloudProps> = ({
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
  const isGrantedToSettings = useGranted([SETTINGS_SETACCESSES, SETTINGS_SECURITYACTIVITY, VIRTUAL_ORGANIZATION_ADMIN]);
  const isEnterpriseEdition = useEnterpriseEdition();
  const buildQueryVariables = useCallback((
    resolvedDataSelection: WidgetDataSelection[],
    _config: DashboardConfig,
    _parameters?: WidgetParameters,
  ): AuditsWordCloudDistributionQuery['variables'] => {
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

  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<AuditsWordCloudDistributionQuery>({
    perspective: 'audits',
    dataSelection,
    host,
    refreshRate,
    query: auditsWordCloudDistributionQuery,
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
        <AuditsWordCloudComponent
          queryRef={queryRef}
          selection={selection}
        />
      </Suspense>
    );
  };

  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? t_i18n('Distribution of history')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default AuditsWordCloud;
