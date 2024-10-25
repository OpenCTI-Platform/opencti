import { renderToString } from 'react-dom/server';
import React from 'react';
import { fetchQuery } from '../../../../relay/environment';
import { StixCoreObjectsAttributesQuery$data } from './__generated__/StixCoreObjectsAttributesQuery.graphql';
import type { TemplateWidget } from '../../template';
import stixCoreObjectsAttributesQuery from './StixCoreObjectsAttributesQuery';
import getObjectProperty from '../../../object';

const buildAttributesOutcome = async (containerId: string, templateWidget: TemplateWidget) => {
  const instanceId = templateWidget.widget.dataSelection[0].instance_id;
  if (!instanceId) {
    throw Error('The attribute widget should refers to an instance');
  }
  const queryVariables = { id: instanceId === 'CONTAINER_ID' ? containerId : instanceId };
  const columns = templateWidget.widget.dataSelection[0].columns ?? [];
  const data = await fetchQuery(stixCoreObjectsAttributesQuery, queryVariables).toPromise() as StixCoreObjectsAttributesQuery$data;
  const attributeOutcomes = columns.map((col) => {
    const result = getObjectProperty(data.stixCoreObject ?? {}, col.attribute) ?? '';
    let attributeData: string;
    if (Array.isArray(result)) {
      if (col.displayStyle && col.displayStyle === 'list') {
        attributeData = renderToString(<ul>{result.map((el) => <li key={el}>{el}</li>)}</ul>);
      } else {
        attributeData = result.join(', ');
      }
    } else {
      attributeData = typeof result === 'string' ? result : result.toString();
    }
    return {
      variableName: col.variableName,
      attributeData,
    };
  });
  return attributeOutcomes;
};

export default buildAttributesOutcome;
