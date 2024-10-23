import { renderToString } from 'react-dom/server';
import React from 'react';
import { fetchQuery } from '../../../../relay/environment';
import { StixCoreObjectsAttributesQuery$data } from './__generated__/stixCoreObjectsAttributesQuery.graphql';
import { TemplateWidget } from '../../template';
import { stixCoreObjectsAttributesQuery } from './StixCoreObjectsAttributes';

const buildAttributesOutcome = async (containerId: string, templateWidgets: TemplateWidget[]) => {
  // if (templateWidgets.some((w) => w.widget.dataSelection[0].instance_id !== 'CONTAINER_ID')) {
  //   throw Error('The attribute widget should refers to the container');
  // }
  const widgetsInfo = templateWidgets.map((w) => ({
    variableName: w.name,
    attribute: w.widget.dataSelection[0].columns[0].attribute,
  }));
  const data = await fetchQuery(stixCoreObjectsAttributesQuery, { id: containerId }).toPromise() as StixCoreObjectsAttributesQuery$data;
  const attributeWidgetsOutcome = widgetsInfo.map((col) => {
    const { attribute } = col;
    const splittedAttribute = col.attribute.split('.');
    const result = splittedAttribute.length === 1 ? data.stixCoreObject?.[attribute] : data.stixCoreObject?.[attribute[0]]?.[attribute[1]];
    let attributeData = '';
    if (!Array.isArray(result)) {
      attributeData = result;
    } else if (col.displayStyle && col.displayStyle === 'list') {
      attributeData = renderToString(<ul>{result.map((el) => <li key={el}>{el}</li>)}</ul>);
    } else {
      attributeData = result.join(', ');
    }
    return { variableName: col.variableName, attributeData };
  });
  return attributeWidgetsOutcome;
};

export default buildAttributesOutcome;
