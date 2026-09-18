import useBuildListOutcome from './stix_core_objects/useBuildListOutcome';
import useDonutOutcome from './stix_relationships/useDonutOutcome';
import { fetchQuery, MESSAGING$ } from '../../../relay/environment';
import engineFintelTemplateQuery from './EngineFintelTemplateQuery';
import useBuildAttributesOutcome from './stix_core_objects/useBuildAttributesOutcome';
import { useFormatter } from '../../../components/i18n';
import { useBuildFiltersForTemplateWidgets } from '../../filters/filtersUtils';
import { EngineFintelTemplateQuery$data } from './__generated__/EngineFintelTemplateQuery.graphql';
import { buildTemplateContentWithOptionalSectionPruning, BuildFileFromTemplateOptions, isSemanticallyEmptyHtmlFragment, TemplateVariableResolution } from './templateSectionUtils';
import type { ListOutcome } from './stix_core_objects/useBuildListOutcome';
import type { DonutOutcome } from './stix_relationships/useDonutOutcome';

type WidgetOutcome = ListOutcome | DonutOutcome;

const normalizeWidgetOutcome = (outcome: string | WidgetOutcome): WidgetOutcome => {
  if (typeof outcome === 'string') {
    return {
      html: outcome,
      isEmpty: isSemanticallyEmptyHtmlFragment(outcome),
    };
  }

  return outcome;
};

const applyTemplateVariableResolutions = (
  templateContent: string,
  resolutions: TemplateVariableResolution[],
) => {
  return resolutions.reduce((nextTemplateContent, resolution) => {
    const token = `$${resolution.variableName}`;
    return resolution.replaceAll
      ? nextTemplateContent.replaceAll(token, resolution.replacement)
      : nextTemplateContent.replace(token, resolution.replacement);
  }, templateContent);
};

const useFileFromTemplate = () => {
  const { t_i18n } = useFormatter();
  const { buildDonutOutcome } = useDonutOutcome();
  const { buildListOutcome } = useBuildListOutcome();
  const { buildAttributesOutcome } = useBuildAttributesOutcome();
  const { buildFiltersForTemplateWidgets } = useBuildFiltersForTemplateWidgets();

  type Template = EngineFintelTemplateQuery$data['fintelTemplate'];

  const resolveDataWidgetOutcome = async (
    containerId: string,
    maxContentMarkings: string[],
    templateWidget: NonNullable<NonNullable<Template>['fintel_template_widgets']>[number],
    includeMetadata: boolean,
  ): Promise<TemplateVariableResolution[]> => {
    const { widget } = templateWidget;

    if (widget.type === 'attribute') {
      try {
        const attributesOutcomes = await buildAttributesOutcome(
          containerId,
          widget.dataSelection[0],
          includeMetadata ? { includeMetadata: true } : undefined,
        );

        return attributesOutcomes.flatMap((outcome) => {
          if (outcome.error) {
            MESSAGING$.notifyError(`One of the attribute widgets resolution raised an error. ${outcome.error}`);
          }

          if (!outcome.variableName) {
            return [];
          }

          return [{
            variableName: outcome.variableName,
            replacement: outcome.attributeData,
            isEmpty: includeMetadata ? outcome.isEmpty : false,
            preserveSection: includeMetadata ? outcome.preserveSection : undefined,
            replaceAll: true,
          }];
        });
      } catch (error) {
        MESSAGING$.notifyError(`One of the attribute widgets resolution raised an error. ${error}`);
        return [];
      }
    }

    const filters = buildFiltersForTemplateWidgets(widget.dataSelection[0]?.filters ?? undefined, containerId, maxContentMarkings);

    try {
      let outcome: WidgetOutcome;
      if (widget.type === 'list') {
        outcome = includeMetadata
          ? normalizeWidgetOutcome(await buildListOutcome(
              {
                ...widget.dataSelection[0],
                filters,
              },
              widget.perspective,
              { includeMetadata: true },
            ))
          : {
              html: await buildListOutcome(
                {
                  ...widget.dataSelection[0],
                  filters,
                },
                widget.perspective,
              ),
              isEmpty: false,
            };
      } else {
        const { dynamicFrom, dynamicTo } = widget.dataSelection[0];
        outcome = includeMetadata
          ? normalizeWidgetOutcome(await buildDonutOutcome({
              ...widget.dataSelection[0],
              filters,
              dynamicFrom: dynamicFrom ? JSON.parse(dynamicFrom) : undefined,
              dynamicTo: dynamicTo ? JSON.parse(dynamicTo) : undefined,
            }, { includeMetadata: true }))
          : {
              html: await buildDonutOutcome({
                ...widget.dataSelection[0],
                filters,
                dynamicFrom: dynamicFrom ? JSON.parse(dynamicFrom) : undefined,
                dynamicTo: dynamicTo ? JSON.parse(dynamicTo) : undefined,
              }),
              isEmpty: false,
            };
      }

      return [{
        variableName: templateWidget.variable_name,
        replacement: outcome.html,
        isEmpty: includeMetadata ? outcome.isEmpty : false,
      }];
    } catch (error) {
      MESSAGING$.notifyError(t_i18n('One of the widgets has not been resolved.'));
      return [{
        variableName: templateWidget.variable_name,
        replacement: `${t_i18n('An error occurred while retrieving data for this widget:')}${error ?? ''}`,
        isEmpty: false,
        preserveSection: includeMetadata,
      }];
    }
  };

  const collectTemplateVariableResolutions = async (
    containerId: string,
    maxContentMarkings: string[],
    templateWidgets: NonNullable<NonNullable<Template>['fintel_template_widgets']>,
    includeMetadata: boolean,
  ) => {
    const resolutions: TemplateVariableResolution[] = [];

    for (const templateWidget of templateWidgets) {
      resolutions.push(...await resolveDataWidgetOutcome(
        containerId,
        maxContentMarkings,
        templateWidget,
        includeMetadata,
      ));
    }

    return resolutions;
  };

  const buildFileFromTemplate = async (
    containerId: string,
    maxContentMarkings: string[],
    templateId?: string,
    template?: Template,
    options?: BuildFileFromTemplateOptions,
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

    const { template_content } = fintelTemplate;
    const { fintel_template_widgets } = fintelTemplate;

    const variableResolutions = await collectTemplateVariableResolutions(
      containerId,
      maxContentMarkings,
      fintel_template_widgets,
      !!options?.removeEmptySections,
    );

    if (!options?.removeEmptySections) {
      return applyTemplateVariableResolutions(template_content, variableResolutions);
    }

    return buildTemplateContentWithOptionalSectionPruning(
      template_content,
      variableResolutions,
      options,
    );
  };

  return { buildFileFromTemplate };
};

export default useFileFromTemplate;
