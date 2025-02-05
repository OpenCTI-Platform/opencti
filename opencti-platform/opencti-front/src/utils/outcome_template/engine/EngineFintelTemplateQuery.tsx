import { graphql } from 'react-relay';

const engineFintelTemplateQuery = graphql`
  query EngineFintelTemplateQuery($id: ID!) {
    fintelTemplate(id: $id) {
        template_content
        instance_filters
        fintel_template_widgets {
          variable_name
          widget {
            type
            perspective
            dataSelection {
              number
              attribute
              date_attribute
              isTo
              filters
              dynamicFrom
              dynamicTo
              columns {
                attribute
                displayStyle
                variableName
                label
              }
              instance_id
            }
        }
      }
    }
  }
`;

export default engineFintelTemplateQuery;
