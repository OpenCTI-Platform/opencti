import type { Template, TemplateWidget } from '../template';
import { ResolvedAttributesWidgets } from '../template';
import buildListOutcome from './stix_core_objects/list';
import useDonutOutcome from './stix_relationships/donut';

const useOutcomeTemplate = () => {
  const { buildDonutOutcome } = useDonutOutcome();

  const buildOutcomeTemplate = async (
    containerId: string,
    template: Template,
    usedTemplateWidgets: TemplateWidget[],
    resolvedAttributesWidgets: ResolvedAttributesWidgets[],
  ) => {
    let { content } = template;

    // attribute widgets
    for (const attributeWidget of resolvedAttributesWidgets) {
      content = content.replace(`$${attributeWidget.template_widget_name}`, attributeWidget.data);
    }

    // other widgets
    for (const templateWidget of usedTemplateWidgets) {
      let outcome = '';
      if (templateWidget.widget.type === 'list') {
        // eslint-disable-next-line no-await-in-loop
        outcome = await buildListOutcome(
          containerId,
          templateWidget.widget,
        );
        // outcome = await buildListOutcome(containerId, templateWidget.widget, rootRef);
      } else if (templateWidget.widget.type === 'donut') {
        // eslint-disable-next-line no-await-in-loop
        outcome = await buildDonutOutcome(containerId, templateWidget.widget);
      }
      content = content.replace(`$${templateWidget.name}`, outcome);
    }

    return content;
  };

  return { buildOutcomeTemplate };
};

export default useOutcomeTemplate;
