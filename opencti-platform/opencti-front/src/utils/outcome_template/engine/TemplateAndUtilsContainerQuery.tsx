import { graphql } from 'react-relay';

const templateAndUtilsContainerQuery = graphql`
  query TemplateAndUtilsContainerQuery($id: String!, $templateId: String!) {
    container(id: $id) {
      id
      templateAndUtils(templateId: $templateId) {
        template {
          id
          name
          template_widgets_ids
          content
          filters
        }
        template_widgets {
          name
          widget {
              id
              type
              perspective
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
  }
`;
export default templateAndUtilsContainerQuery;
