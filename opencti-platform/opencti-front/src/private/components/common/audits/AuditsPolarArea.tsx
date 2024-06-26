/*
Copyright (c) 2021-2024 Filigran SAS

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
import React, { CSSProperties } from 'react';
import { AuditsPolarAreaDistributionQuery } from '@components/common/audits/__generated__/AuditsPolarAreaDistributionQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../../components/dashboard/WidgetLoader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetPolarArea from '../../../../components/dashboard/WidgetPolarArea';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import useGranted, { SETTINGS_SECURITYACTIVITY, SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../../../../utils/hooks/useGranted';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import WidgetAccessDenied from '../../../../components/dashboard/WidgetAccessDenied';
import { DashboardWidgetDataSelection, DashboardWidgetParameters } from '../../../../utils/dashboard';

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
  dataSelection: DashboardWidgetDataSelection[]
  queryRef: PreloadedQuery<AuditsPolarAreaDistributionQuery>
  withExportPopover: boolean
  isReadOnly: boolean
}

const AuditsPolarAreaComponent = ({
  dataSelection,
  queryRef,
  withExportPopover,
  isReadOnly,
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
        withExport={withExportPopover}
        readonly={isReadOnly}
      />
    );
  }
  return <WidgetNoData />;
};

interface AuditsPolarAreaProps {
  startDate: string
  endDate: string
  dataSelection: DashboardWidgetDataSelection[]
  parameters: DashboardWidgetParameters
  variant: string
  height?: CSSProperties['height']
  withExportPopover?: boolean
  isReadOnly?: boolean
}

const AuditsPolarAreaQueyRef = ({
  startDate,
  endDate,
  dataSelection,
  parameters,
  height,
  variant,
  withExportPopover = false,
  isReadOnly = false,
}: AuditsPolarAreaProps) => {
  const selection = dataSelection[0];
  const { t_i18n } = useFormatter();

  const queryRef = useQueryLoading<AuditsPolarAreaDistributionQuery>(
    auditsPolarAreaDistributionQuery,
    {
      types: ['History', 'Activity'],
      field: selection.attribute || 'entity_type',
      operation: 'count',
      startDate,
      endDate,
      dateAttribute:
        selection.date_attribute && selection.date_attribute.length > 0
          ? selection.date_attribute
          : 'timestamp',
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore Excepts readonly array as variables but have simple array.
      filters: selection.filters,
      limit: selection.number ?? 10,
    },
  );

  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? t_i18n('Distribution of history')}
      variant={variant}
    >
      {queryRef ? (
        <React.Suspense fallback={<WidgetLoader />}>
          <AuditsPolarAreaComponent
            queryRef={queryRef}
            dataSelection={dataSelection}
            withExportPopover={withExportPopover}
            isReadOnly={isReadOnly}
          />
        </React.Suspense>
      ) : (
        <WidgetLoader />
      )}
    </WidgetContainer>
  );
};

const AuditsPolarArea = (props: AuditsPolarAreaProps) => {
  const { t_i18n } = useFormatter();
  const isGrantedToSettings = useGranted([SETTINGS_SETACCESSES, SETTINGS_SECURITYACTIVITY, VIRTUAL_ORGANIZATION_ADMIN]);
  const isEnterpriseEdition = useEnterpriseEdition();

  if (!isGrantedToSettings || !isEnterpriseEdition) {
    const { height, parameters, variant } = props;
    return (
      <WidgetContainer
        height={height}
        title={parameters.title ?? t_i18n('Distribution of history')}
        variant={variant}
      >
        <WidgetAccessDenied />
      </WidgetContainer>
    );
  }
  return <AuditsPolarAreaQueyRef {...props} />;
};

export default AuditsPolarArea;
