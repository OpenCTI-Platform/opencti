import useBuildListOutcome from './stix_core_objects/useBuildListOutcome';
import useDonutOutcome from './stix_relationships/useDonutOutcome';
import { fetchQuery, MESSAGING$ } from '../../../relay/environment';
import { TemplateAndUtilsContainerQuery$data } from './__generated__/TemplateAndUtilsContainerQuery.graphql';
import templateAndUtilsContainerQuery from './TemplateAndUtilsContainerQuery';
import useBuildAttributesOutcome from './stix_core_objects/useBuildAttributesOutcome';
import { useFormatter } from '../../../components/i18n';

const useContentFromTemplate = () => {
  const { t_i18n } = useFormatter();
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
    const { container } = await fetchQuery(
      templateAndUtilsContainerQuery,
      variables,
    ).toPromise() as TemplateAndUtilsContainerQuery$data;

    if (!container || !container.templateAndUtils) {
      throw Error('No template found');
    }

    const { template, template_widgets } = container.templateAndUtils;
    let { content } = template;

    for (const templateWidget of template_widgets) {
      const { widget } = templateWidget;

      // attribute widgets
      if (widget.type === 'attribute') {
        // eslint-disable-next-line no-await-in-loop
        const attributesOutcomes = await buildAttributesOutcome(
          containerId,
          widget.dataSelection[0],
        );
        for (const outcome of attributesOutcomes) {
          content = content.replace(`$${outcome.variableName}`, outcome.attributeData);
        }
      // other widgets
      } else {
        let outcome = '';
        try {
          if (widget.type === 'list') {
            // eslint-disable-next-line no-await-in-loop
            outcome = await buildListOutcome(
              maxContentMarkings,
              {
                ...widget.dataSelection[0],
                filters: JSON.parse(widget.dataSelection[0]?.filters ?? '{}'),
              },
            );
          } else if (widget.type === 'donut') {
            // eslint-disable-next-line no-await-in-loop
            outcome = await buildDonutOutcome(widget, maxContentMarkings);
          }
        } catch (error) {
          outcome = `${t_i18n('An error occured while retrieving data for this widget:')}${error ?? ''}`;
          MESSAGING$.notifyError('One of the widgets has not been resolved.');
        }
        content = content.replace(`$${templateWidget.id}`, outcome);
      }
    }

    return content;
  };

  return { buildContentFromTemplate };
};

export default useContentFromTemplate;
