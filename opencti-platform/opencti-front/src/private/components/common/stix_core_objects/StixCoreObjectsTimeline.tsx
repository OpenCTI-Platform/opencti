import React from 'react';
import { graphql } from 'react-relay';
import { StixCoreObjectsTimelineQuery$data } from './__generated__/StixCoreObjectsTimelineQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetTimeline from '../../../../components/dashboard/WidgetTimeline';
import { resolveLink } from '../../../../utils/Entity';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { WidgetDataSelection, WidgetParameters } from '../../../../utils/widget/widget';

const stixCoreObjectsTimelineQuery = graphql`
  query StixCoreObjectsTimelineQuery(
    $types: [String]
    $first: Int
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    stixCoreObjects(
      types: $types
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) {
      edges {
        node {
          id
          entity_type
          created_at
          updated_at
          ... on StixDomainObject  {
            modified
            created
          }
          ... on Event {
            start_time
            stop_time
          }
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          representative {
            main
            secondary
          }
        }
      }
    }
  }
`;

interface StixCoreObjectsTimelineProps {
  variant: string,
  height?: number,
  startDate: string | null,
  endDate: string | null,
  dataSelection: WidgetDataSelection[],
  parameters?: WidgetParameters,
}

const StixCoreObjectsTimeline = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
}: StixCoreObjectsTimelineProps) => {
  const { t_i18n } = useFormatter();
  const renderContent = () => {
    const selection = dataSelection[0];
    const dataSelectionTypes = ['Stix-Core-Object'];
    const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
      ? selection.date_attribute
      : 'created_at';
    const { filters } = buildFiltersAndOptionsForWidgets(selection.filters, { startDate, endDate, dateAttribute });
    return (
      <QueryRenderer
        query={stixCoreObjectsTimelineQuery}
        variables={{
          types: dataSelectionTypes,
          first: selection.number ?? 10,
          orderBy: dateAttribute,
          orderMode: selection.sort_mode ?? 'desc',
          filters,
        }}
        render={({ props }: { props: StixCoreObjectsTimelineQuery$data }) => {
          if (
            props
            && props.stixCoreObjects
            && props.stixCoreObjects.edges.length > 0
          ) {
            const stixCoreObjectsEdges = props.stixCoreObjects.edges;
            const data = stixCoreObjectsEdges.map((stixCoreObjectEdge) => {
              const stixCoreObject = stixCoreObjectEdge.node;
              const link = `${resolveLink(stixCoreObject.entity_type)}/${stixCoreObject.id}`;
              return {
                value: stixCoreObject,
                link,
              };
            });
            return <WidgetTimeline data={data} dateAttribute={dateAttribute} />;
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
      title={parameters.title ?? t_i18n('Entities list')}
      variant={variant}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixCoreObjectsTimeline;
