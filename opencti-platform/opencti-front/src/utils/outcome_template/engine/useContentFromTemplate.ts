import useBuildListOutcome from './stix_core_objects/useBuildListOutcome';
import useDonutOutcome from './stix_relationships/useDonutOutcome';
import { fetchQuery } from '../../../relay/environment';
import { templateAndUtilsContainerQuery } from './TemplateAndUtils';
import { TemplateAndUtilsContainerQuery } from './__generated__/TemplateAndUtilsContainerQuery.graphql';

const useContentFromTemplate = () => {
  const { buildDonutOutcome } = useDonutOutcome();
  const { buildListOutcome } = useBuildListOutcome();

  const buildContentFromTemplate = async (
    containerId: string,
    templateName: string,
    maxContentMarkings: string[],
  ) => {
    const variables = { id: containerId, templateId: templateName };
    const data = await fetchQuery<TemplateAndUtilsContainerQuery>(templateAndUtilsContainerQuery, variables).toPromise();
    const { template, template_widgets, resolved_widgets_attributes } = data.container.templateAndUtils;
    let { content } = template;

    // attribute widgets
    for (const attributeWidget of resolved_widgets_attributes) {
      if (attributeWidget.template_widget_name && attributeWidget.data) {
        content = content.replace(`$${attributeWidget.template_widget_name}`, attributeWidget.data[0]);
      }
    }

    // other widgets
    for (const templateWidget of template_widgets) {
      let outcome = '';
      const widget = JSON.parse(templateWidget.widget);
      if (widget.type === 'list') {
        // eslint-disable-next-line no-await-in-loop
        outcome = await buildListOutcome(
          containerId,
          widget,
          maxContentMarkings,
        );
      } else if (widget.type === 'donut') {
        // eslint-disable-next-line no-await-in-loop
        outcome = await buildDonutOutcome(containerId, widget, maxContentMarkings);
      }
      content = content.replace(`$${templateWidget.name}`, outcome);
    }

    return content;
  };

  return { buildContentFromTemplate };
};

export default useContentFromTemplate;
