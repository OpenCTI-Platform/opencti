import { graphql } from 'react-relay';

const fintelTemplateQuery = graphql`
  query FintelTemplateQuery($id: ID!) {
      fintelTemplate(id: $id) {
          id
          name
          content
          instance_filters
          fintel_template_widgets {
              id
              variable_name
              widget {
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
export default fintelTemplateQuery;
