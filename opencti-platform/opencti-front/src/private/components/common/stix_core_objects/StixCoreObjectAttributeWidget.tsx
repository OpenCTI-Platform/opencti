import React from 'react';
import { graphql } from 'react-relay';
import WidgetAttribute from '@components/workspaces/dashboards/WidgetAttribute';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { removeEntityTypeAllFromFilterGroup } from '../../../../utils/filters/filtersUtils';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetLoader from '../../../../components/dashboard/WidgetLoader';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';

const stixCoreObjectAttributeQuery = graphql`
    query StixCoreObjectAttributeWidgetQuery(
        $id: String!
    ) {
        stixCoreObject(
            id: $id
        ) {
            id
            entity_type
            parent_types
            representative {
                main
                secondary
            }
            objectMarking {
                id
                standard_id
                entity_type
                definition_type
                definition
                created
                modified
                x_opencti_order
                x_opencti_color
            }
            objectLabel {
                id
                value
                color
            }
            ... on Report {
                name
                description
                report_types
                published
            }
        }
    }
`;

const stixCoreObjectAttributeMultipleQuery = graphql`
    query StixCoreObjectAttributeWidgetMultipleQuery(
        $filters: FilterGroup
    ) {
        stixCoreObjects(
            filters: $filters
        ) {
            edges {
              node {
                  id
                  entity_type
                  representative {
                      main
                      secondary
                  }
                  ... on Report {
                      name
                      description
                      report_types
                      published
                  }
              }
          }
        }
    }
`;

const StixCoreObjectAttributeWidget = ({
  variant,
  height,
  dataSelection,
  parameters = {},
}) => {
  const { t_i18n } = useFormatter();
  const renderContent = () => {
    const selection = dataSelection[0];
    return (
      <QueryRenderer
        query={stixCoreObjectAttributeMultipleQuery}
        variables={{
          first: 50,
          filters: removeEntityTypeAllFromFilterGroup(selection.filters),
        }}
        render={({ props }) => {
          if (props && props.stixCoreObjects && props.stixCoreObjects.edges.length > 0) {
            const data = props.stixCoreObjects.edges.map((n) => n.node);
            return <WidgetAttribute data={data} attribute={dataSelection.length === 1 ? dataSelection[0].attribute : undefined} />;
          }
          if (props) {
            return <WidgetNoData />;
          }
          return <WidgetLoader />;
        }}
      />
    );
  };
  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? t_i18n('Attributes')}
      variant={variant}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixCoreObjectAttributeWidget;
