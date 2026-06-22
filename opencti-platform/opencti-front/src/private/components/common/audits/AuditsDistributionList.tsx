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

import React, { FunctionComponent, ReactNode, Suspense, useCallback } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { AuditsDistributionListDistributionQuery } from '@components/common/audits/__generated__/AuditsDistributionListDistributionQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { getMainRepresentative, isFieldForIdentifier } from '../../../../utils/defaultRepresentatives';
import useGranted, { SETTINGS_SECURITYACTIVITY, SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../../../../utils/hooks/useGranted';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetDistributionList from '../../../../components/dashboard/WidgetDistributionList';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import WidgetAccessDenied from '../../../../components/dashboard/WidgetAccessDenied';

const auditsDistributionListDistributionQuery = graphql`
  query AuditsDistributionListDistributionQuery(
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
        ... on InternalObject {
          representative {
            main
          }
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
          entity_type
          name
        }
        ... on Group {
          name
        }
      }
    }
  }
`;

interface AuditsDistributionListComponentProps {
  queryRef: PreloadedQuery<AuditsDistributionListDistributionQuery>;
  selection: WidgetDataSelection;
  hasSetAccess: boolean;
}

type DistributionNode = NonNullable<
  NonNullable<AuditsDistributionListDistributionQuery['response']['auditsDistribution']>[number]
>;

const AuditsDistributionListComponent: FunctionComponent<AuditsDistributionListComponentProps> = ({
  queryRef,
  selection,
  hasSetAccess,
}) => {
  const { t_i18n } = useFormatter();

  const data = usePreloadedQuery<AuditsDistributionListDistributionQuery>(
    auditsDistributionListDistributionQuery,
    queryRef,
  );

  if (!data.auditsDistribution || data.auditsDistribution.length === 0) {
    return <WidgetNoData />;
  }

  const mappedData = data.auditsDistribution
    .filter((n): n is DistributionNode => n != null)
    .map((n) => {
      let { label } = n;
      let id: string | undefined = undefined;
      let type = n.label;
      const attribute = selection.attribute ?? undefined;
      if (isFieldForIdentifier(attribute)) {
        label = getMainRepresentative(n.entity ?? undefined) || n.label;
        id = n.entity?.id;
        type = n.entity?.entity_type ?? n.label;
      } else if (selection.attribute === 'entity_type' && t_i18n(`entity_${n.label}`) !== `entity_${n.label}`) {
        label = t_i18n(`entity_${n.label}`);
      }
      return {
        label,
        value: n.value,
        id,
        type,
      };
    });

  return <WidgetDistributionList data={mappedData} hasSettingAccess={hasSetAccess} />;
};

interface AuditsDistributionListProps {
  variant?: string;
  height?: number;
  startDate?: string | null;
  endDate?: string | null;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  config: DashboardConfig;
  refreshRate?: number | null;
  popover?: ReactNode;
  host?: WidgetHost;
}

const AuditsDistributionList: FunctionComponent<AuditsDistributionListProps> = ({
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
  const hasSetAccess = useGranted([SETTINGS_SETACCESSES]);
  const isGrantedToSettings = useGranted([SETTINGS_SETACCESSES, SETTINGS_SECURITYACTIVITY, VIRTUAL_ORGANIZATION_ADMIN]);
  const isEnterpriseEdition = useEnterpriseEdition();

  const buildQueryVariables = useCallback((resolvedDataSelection: WidgetDataSelection[]) => {
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

  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<AuditsDistributionListDistributionQuery>({
    perspective: 'audits',
    dataSelection,
    host,
    refreshRate,
    query: auditsDistributionListDistributionQuery,
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
        <AuditsDistributionListComponent
          queryRef={queryRef}
          selection={selection}
          hasSetAccess={hasSetAccess}
        />
      </Suspense>
    );
  };

  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? t_i18n('Distribution of entities')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default AuditsDistributionList;
