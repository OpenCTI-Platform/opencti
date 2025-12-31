import React from 'react';
import { graphql } from 'react-relay';
import { StixRelationshipsDonutDistributionQuery$data } from '@components/common/stix_relationships/__generated__/StixRelationshipsDonutDistributionQuery.graphql';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetDonut from '../../../../components/dashboard/WidgetDonut';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { WidgetDataSelection, WidgetParameters } from '../../../../utils/widget/widget';

export const stixRelationshipsDonutsDistributionQuery = graphql`
  query StixRelationshipsDonutDistributionQuery(
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
    stixRelationshipsDistribution(
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

interface StixRelationshipsDonutProps {
  title?: string;
  variant: string;
  height?: number;
  field?: string;
  startDate: string | null;
  endDate: string | null;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  withExportPopover?: boolean;
  isReadOnly?: boolean;
  withoutTitle?: boolean;
}

const StixRelationshipsDonut = ({
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
}: StixRelationshipsDonutProps) => {
  const { t_i18n } = useFormatter();
  const renderContent = () => {
    let selection;
    let filtersAndOptions;
    if (dataSelection) {
      selection = dataSelection[0];
      filtersAndOptions = buildFiltersAndOptionsForWidgets(selection.filters, { isKnowledgeRelationshipWidget: true });
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
        query={stixRelationshipsDonutsDistributionQuery}
        variables={variables}
        render={({ props }: { props: StixRelationshipsDonutDistributionQuery$data }) => {
          if (
            props
            && props.stixRelationshipsDistribution
            && props.stixRelationshipsDistribution.length > 0
          ) {
            return (
              <WidgetDonut
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                data={props.stixRelationshipsDistribution as any[]}
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
      title={parameters.title ?? title ?? t_i18n('Relationships distribution')}
      variant={variant}
      withoutTitle={withoutTitle}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixRelationshipsDonut;
