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

import React, { CSSProperties, FunctionComponent, ReactNode, Suspense, useState } from 'react';
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
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';

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
        groupBy={selection.attribute}
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
}) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const isGrantedToSettings = useGranted([SETTINGS_SETACCESSES, SETTINGS_SECURITYACTIVITY, VIRTUAL_ORGANIZATION_ADMIN]);
  const isEnterpriseEdition = useEnterpriseEdition();
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode } = useDashboardViz({
    perspective: 'audits',
    dataSelection,
    host,
  });
  const selection = resolvedDataSelection[0];

  const queryRef = useQueryLoading<AuditsDonutDistributionQuery>(
    auditsDonutDistributionQuery,
    {
      types: ['History', 'Activity'],
      field: selection.attribute,
      operation: 'count',
      startDate: startDate ?? undefined,
      endDate: endDate ?? undefined,
      dateAttribute:
        selection.date_attribute && selection.date_attribute.length > 0
          ? selection.date_attribute
          : 'timestamp',
      filters: selection.filters,
      limit: selection.number ?? 10,
    },
  );

  const renderContent = () => {
    if (isMissingHostEntity) {
      return <WidgetNoHostEntity host={host} />;
    }
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
