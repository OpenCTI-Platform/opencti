import useBuildListOutcome from './stix_core_objects/useBuildListOutcome';
import useDonutOutcome from './stix_relationships/useDonutOutcome';
import { fetchQuery } from '../../../relay/environment';
import { TemplateAndUtilsContainerQuery$data } from './__generated__/TemplateAndUtilsContainerQuery.graphql';
import templateAndUtilsContainerQuery from './TemplateAndUtilsContainerQuery';
import useBuildAttributesOutcome from './stix_core_objects/useBuildAttributesOutcome';

const useContentFromTemplate = () => {
  const { buildDonutOutcome } = useDonutOutcome();
  const { buildListOutcome } = useBuildListOutcome();
  const { buildAttributesOutcome } = useBuildAttributesOutcome();

  const buildContentFromTemplate = async (
    containerId: string,
    templateId: string,
    maxContentMarkings: string[],
  ) => {
    // fetch template and useful widgets
    const variables = { id: containerId, templateId };
    const { container } = await fetchQuery(templateAndUtilsContainerQuery, variables).toPromise() as TemplateAndUtilsContainerQuery$data;

    if (!container || !container.templateAndUtils) {
      throw Error('No template found');
    }

    const { template, template_widgets } = container.templateAndUtils;
    let { content } = template;

    // attribute widgets
    const attributeWidgets = template_widgets.filter((tw) => tw.widget.type === 'attribute');
    if (attributeWidgets.length > 0) {
      const attributeWidgetsOutcomesPromises = attributeWidgets.map((aw) => buildAttributesOutcome(containerId, aw));
      const attributeWidgetsOutcomes = await Promise.all(attributeWidgetsOutcomesPromises);
      attributeWidgetsOutcomes.flat().forEach((attributeOutcome) => {
        content = content.replace(`$${attributeOutcome.variableName}`, attributeOutcome.attributeData);
      });
    }

    // other widgets
    for (const templateWidget of template_widgets) {
      let outcome = '';
      const { widget } = templateWidget;
      if (widget.type === 'list') {
        // eslint-disable-next-line no-await-in-loop
        outcome = await buildListOutcome(containerId, widget, maxContentMarkings);
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
