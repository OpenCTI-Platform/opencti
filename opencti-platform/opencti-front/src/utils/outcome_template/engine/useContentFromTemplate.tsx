import { renderToString } from 'react-dom/server';
import React from 'react';
import useBuildListOutcome from './stix_core_objects/useBuildListOutcome';
import useDonutOutcome from './stix_relationships/useDonutOutcome';
import { fetchQuery } from '../../../relay/environment';
import { templateAndUtilsContainerQuery } from './TemplateAndUtils';
import { TemplateAndUtilsContainerQuery$data } from './__generated__/TemplateAndUtilsContainerQuery.graphql';

const useContentFromTemplate = () => {
  const { buildDonutOutcome } = useDonutOutcome();
  const { buildListOutcome } = useBuildListOutcome();

  const buildContentFromTemplate = async (
    containerId: string,
    templateName: string,
    maxContentMarkings: string[],
  ) => {
    const variables = { id: containerId, templateId: templateName };
    const { container } = await fetchQuery(templateAndUtilsContainerQuery, variables).toPromise() as TemplateAndUtilsContainerQuery$data;

    if (!container || !container.templateAndUtils) {
      throw Error('No template found');
    }

    const { template, template_widgets, resolved_widgets_attributes } = container.templateAndUtils;
    let { content } = template;

    // attribute widgets
    for (const { data, displayStyle, template_widget_name } of resolved_widgets_attributes) {
      let attributeData = '';
      if (data.length === 1) {
        [attributeData] = data;
      } else if (data.length > 1) {
        if (displayStyle === 'list') {
          attributeData = renderToString(<ul>{data.map((el) => <li key={el}>{el}</li>)}</ul>);
        } else {
          attributeData = data.join(', ');
        }
      }
      content = content.replace(`$${template_widget_name}`, attributeData);
    }

    // other widgets
    for (const templateWidget of template_widgets) {
      let outcome = '';
      const widget = JSON.parse(templateWidget.widget);
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
