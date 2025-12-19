import useBuildListOutcome from './stix_core_objects/useBuildListOutcome';
import useDonutOutcome from './stix_relationships/useDonutOutcome';
import { fetchQuery, MESSAGING$ } from '../../../relay/environment';
import engineFintelTemplateQuery from './EngineFintelTemplateQuery';
import useBuildAttributesOutcome from './stix_core_objects/useBuildAttributesOutcome';
import { useFormatter } from '../../../components/i18n';
import { useBuildFiltersForTemplateWidgets } from '../../filters/filtersUtils';
import { EngineFintelTemplateQuery$data } from './__generated__/EngineFintelTemplateQuery.graphql';

const useFileFromTemplate = () => {
  const { t_i18n } = useFormatter();
  const { buildDonutOutcome } = useDonutOutcome();
  const { buildListOutcome } = useBuildListOutcome();
  const { buildAttributesOutcome } = useBuildAttributesOutcome();
  const { buildFiltersForTemplateWidgets } = useBuildFiltersForTemplateWidgets();

  type Template = EngineFintelTemplateQuery$data['fintelTemplate'];

  const buildFileFromTemplate = async (
    containerId: string,
    maxContentMarkings: string[],
    templateId?: string,
    template?: Template,
  ) => {
    let fintelTemplate: Template;
    if (template) {
      fintelTemplate = template;
    } else if (templateId) {
      const variables = { id: templateId };
      const data = await fetchQuery(
        engineFintelTemplateQuery,
        variables,
      ).toPromise() as EngineFintelTemplateQuery$data;
      fintelTemplate = data.fintelTemplate;
    }

    if (!fintelTemplate) {
      throw Error('No fintel template found');
    }

    let { template_content } = fintelTemplate;
    const { fintel_template_widgets } = fintelTemplate;

    for (const templateWidget of fintel_template_widgets) {
      const { widget } = templateWidget;
      // attribute widgets
      if (widget.type === 'attribute') {
        try {
          const attributesOutcomes = await buildAttributesOutcome(
            containerId,
            widget.dataSelection[0],
          );
          for (const outcome of attributesOutcomes) {
            template_content = template_content.replaceAll(`$${outcome.variableName}`, outcome.attributeData as string);
          }
        } catch (error) {
          MESSAGING$.notifyError(`One of the attribute widgets resolution raised an error. ${error}`);
        }
      // other widgets
      } else {
        let outcome = '';
        const filters = buildFiltersForTemplateWidgets(widget.dataSelection[0]?.filters ?? undefined, containerId, maxContentMarkings);
        try {
          if (widget.type === 'list') {
            outcome = await buildListOutcome(
              {
                ...widget.dataSelection[0],
                filters,
              },
              widget.perspective,
            );
          } else if (widget.type === 'donut') {
            const { dynamicFrom, dynamicTo } = widget.dataSelection[0];

            outcome = await buildDonutOutcome({
              ...widget.dataSelection[0],
              filters,
              dynamicFrom: dynamicFrom ? JSON.parse(dynamicFrom) : undefined,
              dynamicTo: dynamicTo ? JSON.parse(dynamicTo) : undefined,
            });
          }
        } catch (error) {
          outcome = `${t_i18n('An error occurred while retrieving data for this widget:')}${error ?? ''}`;
          MESSAGING$.notifyError('One of the widgets has not been resolved.');
        }
        template_content = template_content.replace(`$${templateWidget.variable_name}`, outcome);
      }
    }

    return template_content;
  };

  return { buildFileFromTemplate };
};

export default useFileFromTemplate;
