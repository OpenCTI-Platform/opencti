import { graphql } from 'react-relay';

const templateAndUtilsContainerQuery = graphql`
  query TemplateAndUtilsContainerQuery($id: String!, $templateId: String!) {
    container(id: $id) {
      id
      templateAndUtils(templateId: $templateId) {
        template {
          id
          name
          template_widgets_names
          content
          filters
        }
        template_widgets {
          name
          widget
        }
      }
    }
  }
`;
export default templateAndUtilsContainerQuery;
