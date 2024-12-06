import { graphql } from 'react-relay';

const fintelTemplateAndUtilsContainerQuery = graphql`
  query FintelTemplateAndUtilsContainerQuery($id: String!, $templateId: String!) {
    container(id: $id) {
      id
      fintelTemplateAndUtils(templateId: $templateId) {
        fintelTemplate {
          id
          name
          template_widgets_ids
          content
          instance_filters
        }
        template_widgets {
          id
          type
          perspective
          parameters {
              title
              description
          }
          dataSelection {
              label
              number
              attribute
              date_attribute
              centerLat
              centerLng
              zoom
              isTo
              perspective
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
export default fintelTemplateAndUtilsContainerQuery;
