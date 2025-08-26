import React from 'react';
import { graphql } from 'react-relay';
import { InPirRelationshipsDonutDistributionQuery$data } from '@components/pir/__generated__/InPirRelationshipsDonutDistributionQuery.graphql';
import WidgetDonut from '../../../components/dashboard/WidgetDonut';
import WidgetNoData from '../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../components/Loader';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';
import { QueryRenderer } from '../../../relay/environment';
import { buildFiltersAndOptionsForWidgets } from '../../../utils/filters/filtersUtils';
import type { WidgetDataSelection, WidgetParameters } from '../../../utils/widget/widget';
import { useFormatter } from '../../../components/i18n';

export const inPirRelationshipsDonutsDistributionQuery = graphql`
  query InPirRelationshipsDonutDistributionQuery(
    $pirId: ID!
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $isTo: Boolean
    $limit: Int
    $fromOrToId: [String]
    $elementWithTargetTypes: [String]
    $fromId: [String]
    $fromRole: String
    $fromTypes: [String]
    $toId: [String]
    $toRole: String
    $toTypes: [String]
    $relationship_type: [String]
    $confidences: [Int]
    $search: String
    $filters: FilterGroup
    $dynamicFrom: FilterGroup
    $dynamicTo: FilterGroup
  ) {
    inPirRelationshipsDistribution(
      pirId: $pirId
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      isTo: $isTo
      limit: $limit
      fromOrToId: $fromOrToId
      elementWithTargetTypes: $elementWithTargetTypes
      fromId: $fromId
      fromRole: $fromRole
      fromTypes: $fromTypes
      toId: $toId
      toRole: $toRole
      toTypes: $toTypes
      relationship_type: $relationship_type
      confidences: $confidences
      search: $search
      filters: $filters
      dynamicFrom: $dynamicFrom
      dynamicTo: $dynamicTo
    ) {
      label
      value
      entity {
        id
        entity_type
      }
    }
  }
`;

interface InPirRelationshipsDonutProps {
  title?: string,
  variant: string,
  height?: number,
  field?: string,
  startDate: string | null,
  endDate: string | null,
  dataSelection: WidgetDataSelection[],
  parameters?: WidgetParameters,
  withExportPopover?: boolean,
  isReadOnly?: boolean,
  withoutTitle?: boolean
}

const InPirRelationshipsDonut = ({
  title,
  variant,
  height,
  field,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
  withExportPopover = false,
  isReadOnly = false,
  withoutTitle = false,
}: InPirRelationshipsDonutProps) => {
  const { t_i18n } = useFormatter();
  const renderContent = () => {
    let selection;
    let filtersAndOptions;
    if (dataSelection) {
      // eslint-disable-next-line prefer-destructuring
      selection = dataSelection[0];
      filtersAndOptions = buildFiltersAndOptionsForWidgets(selection.filters);
    }
    const finalField = selection?.attribute || field || 'entity_type';
    const variables = {
      ...selection,
      field: finalField,
      operation: 'count',
      startDate,
      endDate,
      dateAttribute: selection?.date_attribute ?? 'created_at',
      limit: selection?.number ?? 10,
      filters: filtersAndOptions?.filters,
      isTo: selection?.isTo,
      dynamicFrom: selection?.dynamicFrom,
      dynamicTo: selection?.dynamicTo,
    };
    return (
      <QueryRenderer
        query={inPirRelationshipsDonutsDistributionQuery}
        variables={variables}
        render={({ props }: { props: InPirRelationshipsDonutDistributionQuery$data }) => {
          if (
            props
            && props.inPirRelationshipsDistribution
            && props.inPirRelationshipsDistribution.length > 0
          ) {
            return (
              <WidgetDonut
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                data={props.inPirRelationshipsDistribution as any[]}
                groupBy={finalField}
                withExport={withExportPopover}
                readonly={isReadOnly}
              />
            );
          }
          if (props) {
            return <WidgetNoData />;
          }
          return <Loader variant={LoaderVariant.inElement} />;
        }}
      />
    );
  };
  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? title ?? t_i18n('PIR Relationships distribution')}
      variant={variant}
      withoutTitle={withoutTitle}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default InPirRelationshipsDonut;
