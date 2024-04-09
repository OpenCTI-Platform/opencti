import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { CSSProperties } from 'react';
import { StixCoreObjectsPolarAreaDistributionQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsPolarAreaDistributionQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../../components/dashboard/WidgetLoader';
import { useFormatter } from '../../../../components/i18n';
import WidgetPolarArea from '../../../../components/dashboard/WidgetPolarArea';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import { DashboardWidgetDataSelection, DashboardWidgetParameters } from '../../../../utils/dashboard';

const stixCoreObjectsPolarAreaDistributionQuery = graphql`
  query StixCoreObjectsPolarAreaDistributionQuery(
    $objectId: [String]
    $relationship_type: [String]
    $toTypes: [String]
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
    stixCoreObjectsDistribution(
      objectId: $objectId
      relationship_type: $relationship_type
      toTypes: $toTypes
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

interface StixCoreObjectsPolarAreaComponentProps {
  dataSelection: DashboardWidgetDataSelection[]
  queryRef: PreloadedQuery<StixCoreObjectsPolarAreaDistributionQuery>
  withExportPopover: boolean
  isReadOnly: boolean
}

const StixCoreObjectsPolarAreaComponent = ({
  dataSelection,
  queryRef,
  withExportPopover,
  isReadOnly,
}: StixCoreObjectsPolarAreaComponentProps) => {
  const { stixCoreObjectsDistribution } = usePreloadedQuery(
    stixCoreObjectsPolarAreaDistributionQuery,
    queryRef,
  );

  if (
    stixCoreObjectsDistribution
    && stixCoreObjectsDistribution.length > 0
  ) {
    const attributeField = dataSelection[0].attribute || 'entity_type';
    return (
      <WidgetPolarArea
        data={[...stixCoreObjectsDistribution]}
        groupBy={attributeField}
        withExport={withExportPopover}
        readonly={isReadOnly}
      />
    );
  }
  return <WidgetNoData />;
};

interface StixCoreObjectsPolarAreaProps {
  startDate: string
  endDate: string
  dataSelection: DashboardWidgetDataSelection[]
  parameters: DashboardWidgetParameters
  variant?: string
  height?: CSSProperties['height']
  withExportPopover?: boolean
  isReadOnly?: boolean
}

const StixCoreObjectsPolarArea = ({
  startDate,
  endDate,
  dataSelection,
  parameters,
  height,
  variant = 'inLine',
  withExportPopover = false,
  isReadOnly = false,
}: StixCoreObjectsPolarAreaProps) => {
  const { t_i18n } = useFormatter();

  const selection = dataSelection[0];
  const dataSelectionTypes = ['Stix-Core-Object'];

  const queryRef = useQueryLoading<StixCoreObjectsPolarAreaDistributionQuery>(
    stixCoreObjectsPolarAreaDistributionQuery,
    {
      types: dataSelectionTypes,
      field: selection.attribute || 'entity_type',
      operation: 'count',
      startDate,
      endDate,
      dateAttribute:
        selection.date_attribute && selection.date_attribute.length > 0
          ? selection.date_attribute
          : 'created_at',
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore Excepts readonly array as variables but have simple array.
      filters: selection.filters,
      limit: selection.number ?? 10,
    },
  );

  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? t_i18n('Distribution of entities')}
      variant={variant}
    >
      {queryRef ? (
        <React.Suspense fallback={<WidgetLoader />}>
          <StixCoreObjectsPolarAreaComponent
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

export default StixCoreObjectsPolarArea;
