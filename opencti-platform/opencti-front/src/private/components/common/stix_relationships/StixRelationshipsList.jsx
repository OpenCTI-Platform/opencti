import React, { useRef } from 'react';
import { graphql } from 'react-relay';
import { getDefaultWidgetColumns } from '../../widgets/WidgetListsDefaultColumns';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetListRelationships from '../../../../components/dashboard/WidgetListRelationships';
import Loader, { LoaderVariant } from '../../../../components/Loader';

export const stixRelationshipsListSearchQuery = graphql`
  query StixRelationshipsListSearchQuery(
    $search: String
    $fromId: [String]
    $toId: [String]
    $relationship_type: [String]
    $count: Int!
    $filters: FilterGroup
    $dynamicFrom: FilterGroup
    $dynamicTo: FilterGroup
  ) {
    stixRelationships(
      search: $search
      fromId: $fromId
      toId: $toId
      relationship_type: $relationship_type
      first: $count
      filters: $filters
      dynamicFrom: $dynamicFrom
      dynamicTo: $dynamicTo
    ) {
      edges {
        node {
          id
          standard_id
          entity_type
          parent_types
          relationship_type
        }
      }
    }
  }
`;

const stixRelationshipsListQuery = graphql`
  query StixRelationshipsListQuery(
    $relationship_type: [String]
    $fromId: [String]
    $toId: [String]
    $fromTypes: [String]
    $toTypes: [String]
    $first: Int!
    $orderBy: StixRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $dynamicFrom: FilterGroup
    $dynamicTo: FilterGroup
    $search: String
  ) {
    stixRelationships(
      relationship_type: $relationship_type
      fromId: $fromId
      toId: $toId
      fromTypes: $fromTypes
      toTypes: $toTypes
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      dynamicFrom: $dynamicFrom
      dynamicTo: $dynamicTo
      search: $search
    ) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
          relationship_type
          ... on StixCoreRelationship {
            start_time
            stop_time
            objectLabel {
              id
              value
              color
            }
          }
          created_at
          updated_at
          is_inferred
          createdBy {
            ... on Identity {
              name
            }
          }
          objectMarking {
            id
            definition
            x_opencti_order
            x_opencti_color
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
            definition
            x_opencti_order
            x_opencti_color
          }
          from {
            ... on BasicObject {
              id
              entity_type
            }
            ... on BasicRelationship {
              id
              entity_type
            }
            ... on StixCoreObject {
              entity_type
              representative {
                main
              }
              created_at
            }
            ... on StixRelationship {
              created_at
              ... on StixCoreRelationship {
                start_time
                stop_time
              }
              created
            }
            ... on StixRelationship {
              id
              entity_type
              relationship_type
              ... on StixCoreRelationship {
                start_time
                stop_time
              }
              created
              from {
                ... on BasicObject {
                  id
                  entity_type
                }
                ... on BasicRelationship {
                  id
                  entity_type
                }
                ... on StixCoreObject {
                  entity_type
                  representative {
                    main
                  }
                  created_at
                }
                ... on StixRelationship {
                  created_at
                  ... on StixCoreRelationship {
                    start_time
                    stop_time
                  }
                  created
                }
              }
              to {
                ... on BasicObject {
                  id
                  entity_type
                }
                ... on BasicRelationship {
                  id
                  entity_type
                }
                ... on StixCoreObject {
                  entity_type
                  representative {
                    main
                  }
                  created_at
                }
                ... on StixRelationship {
                  created_at
                  ... on StixCoreRelationship {
                    start_time
                    stop_time
                  }
                  created
                }
              }
            }
          }
          to {
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
            ... on StixCoreObject {
              entity_type
              representative {
                main
              }
              created_at
            }
            ... on Creator {
              entity_type
              representative {
                main
              }
            }
            ... on MarkingDefinition {
              x_opencti_color
              x_opencti_order
            }
            ... on StixRelationship {
              created_at
              ... on StixCoreRelationship {
                start_time
                stop_time
              }
              created
            }
            ... on StixRelationship {
              id
              entity_type
              relationship_type
              ... on StixCoreRelationship {
                start_time
                stop_time
              }
              created
              from {
                ... on BasicObject {
                  id
                  entity_type
                }
                ... on BasicRelationship {
                  id
                  entity_type
                }
                ... on StixCoreObject {
                  entity_type
                  representative {
                    main
                  }
                }
              }
              to {
                ... on BasicObject {
                  id
                  entity_type
                }
                ... on BasicRelationship {
                  id
                  entity_type
                }
                ... on StixCoreObject {
                  entity_type
                  representative {
                    main
                  }
                }
              }
            }
          }
        }
      }
    }
  }
`;

const StixRelationshipsList = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  widgetId,
  parameters = {},
}) => {
  const { t_i18n } = useFormatter();
  const renderContent = () => {
    if (!dataSelection) {
      return 'No data selection';
    }
    const selection = dataSelection[0];
    const columns = selection.columns ?? getDefaultWidgetColumns('relationships');

    const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
      ? selection.date_attribute
      : 'created_at';
    const { filters } = buildFiltersAndOptionsForWidgets(selection.filters, { startDate, endDate, dateAttribute });

    const rootRef = useRef(null);

    return (
      <div ref={rootRef} style={{ height: '100%', width: '100%' }}>
        <QueryRenderer
          query={stixRelationshipsListQuery}
          variables={{
            first: 50,
            orderBy: dateAttribute,
            orderMode: 'desc',
            filters,
            dynamicFrom: selection.dynamicFrom,
            dynamicTo: selection.dynamicTo,
          }}
          render={({ props }) => {
            if (
              props
            && props.stixRelationships
            && props.stixRelationships.edges.length > 0
            ) {
              const data = props.stixRelationships.edges;
              return (
                <WidgetListRelationships
                  data={data}
                  widgetId={widgetId}
                  columns={columns}
                  rootRef={rootRef.current ?? undefined}
                />
              );
            }
            if (props) {
              return <WidgetNoData />;
            }
            return <Loader variant={LoaderVariant.inElement} />;
          }}
        />
      </div>
    );
  };
  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? t_i18n('Relationships list')}
      variant={variant}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixRelationshipsList;
