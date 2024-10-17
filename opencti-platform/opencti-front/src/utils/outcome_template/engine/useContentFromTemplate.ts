import type { Template, TemplateWidget, ResolvedAttributesWidgets } from '../template';
import useBuildListOutcome from './stix_core_objects/useBuildListOutcome';
import useDonutOutcome from './stix_relationships/useDonutOutcome';

const useContentFromTemplate = () => {
  const { buildDonutOutcome } = useDonutOutcome();
  const { buildListOutcome } = useBuildListOutcome();

  const buildContentFromTemplate = async (
    containerId: string,
    template: Template,
    templateWidgets: TemplateWidget[],
    resolvedAttributesWidgets: ResolvedAttributesWidgets[],
    maxContentMarkings: string[],
  ) => {
    let { content } = template;

    // attribute widgets
    for (const attributeWidget of resolvedAttributesWidgets) {
      if (attributeWidget.template_widget_name && attributeWidget.data) {
        content = content.replace(`$${attributeWidget.template_widget_name}`, attributeWidget.data);
      }
    }

    // other widgets
    for (const templateWidget of templateWidgets) {
      let outcome = '';
      if (templateWidget.widget.type === 'list') {
        // eslint-disable-next-line no-await-in-loop
        outcome = await buildListOutcome(
          containerId,
          templateWidget.widget,
          maxContentMarkings,
        );
      } else if (templateWidget.widget.type === 'donut') {
        // eslint-disable-next-line no-await-in-loop
        outcome = await buildDonutOutcome(containerId, templateWidget.widget, maxContentMarkings);
      }
      content = content.replace(`$${templateWidget.name}`, outcome);
    }

    return content;
  };

  return { buildContentFromTemplate };
};

export default useContentFromTemplate;
