import { graphql } from 'react-relay';

// eslint-disable-next-line import/prefer-default-export
export const templateAndUtilsContainerQuery = graphql`
    query TemplateAndUtilsContainerQuery($id: String!, $templateId: String!) {
        container(id: $id) {
            id
            templateAndUtils(templateId: $templateId) {
                template {
                    name
                    used_template_widgets_names
                    content
                    filters
                }
                template_widgets {
                    name
                    widget
                }
                resolved_widgets_attributes {
                    template_widget_name
                    data
                }
            }
        }
    }
`;
