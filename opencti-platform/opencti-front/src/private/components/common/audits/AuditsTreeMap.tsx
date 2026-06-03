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
import { AuditsTreeMapDistributionQuery } from '@components/common/audits/__generated__/AuditsTreeMapDistributionQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { SETTINGS_SECURITYACTIVITY, SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../../../../utils/hooks/useGranted';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetTree from '../../../../components/dashboard/WidgetTree';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';

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
        groupBy={selection.attribute}
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

  const queryRef = useQueryLoading<AuditsTreeMapDistributionQuery>(
    auditsTreeMapDistributionQuery,
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
        <AuditsTreeMapComponent
          queryRef={queryRef}
          selection={selection}
          isDistributed={parameters.distributed}
          onMounted={setChart}
        />
      </Suspense>
    );
  };

  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? t_i18n('Distribution of entities')}
      variant={variant}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default AuditsTreeMap;
