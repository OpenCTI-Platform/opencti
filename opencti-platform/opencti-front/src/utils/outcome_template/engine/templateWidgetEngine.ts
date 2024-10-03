import type { Template, TemplateWidget } from '../template';
import { widgetGraph } from './__template';
import buildListOutcome from './stix_core_objects/list';
import useDonutOutcome from './stix_relationships/donut';

const useOutcomeTemplate = () => {
  const { buildDonutOutcome } = useDonutOutcome();

  const buildOutcomeTemplate = async (containerId: string, template: Template) => {
    let { content } = template;

    // Retrieve widgets used in the template, for now, hardcoded
    const templateWidgets: TemplateWidget[] = [widgetGraph];

    for (const templateWidget of templateWidgets) {
      let outcome = '';
      if (templateWidget.widget.type === 'list') {
        // eslint-disable-next-line no-await-in-loop
        outcome = await buildListOutcome(containerId, templateWidget.widget);
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
