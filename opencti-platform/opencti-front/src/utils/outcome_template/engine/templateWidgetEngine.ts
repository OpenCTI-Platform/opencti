import { Template, TemplateWidget } from '../template';
import { widgetGraph, widgetList } from './__template';
import buildDonutOutcome from './stix_relationships/donut';
import buildListOutcome from './stix_core_objects/list';

const buildOutcomeTemplate = async (containerId: string, template: Template) => {
  let { content } = template;

  // Retrieve widgets used in the template, for now, hardcoded
  const templateWidgets: TemplateWidget[] = [widgetGraph];

  for (const templateWidget of templateWidgets) {
    if (templateWidget.widget.type === 'list') {
      const outcome = await buildListOutcome(containerId, templateWidget.widget);
      content = content.replace(`$${templateWidget.name}`, outcome);
    }
    if (templateWidget.widget.type === 'donut') {
      const outcome = await buildDonutOutcome(containerId, templateWidget.widget);
      content = content.replace(`$${templateWidget.name}`, outcome);
    }
  }

  return content;
};

export default buildOutcomeTemplate;
