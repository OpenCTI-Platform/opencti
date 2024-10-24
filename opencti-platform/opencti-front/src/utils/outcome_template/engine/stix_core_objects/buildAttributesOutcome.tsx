import { renderToString } from 'react-dom/server';
import React from 'react';
import { fetchQuery } from '../../../../relay/environment';
import { StixCoreObjectsAttributesQuery$data } from './__generated__/stixCoreObjectsAttributesQuery.graphql';
import { TemplateWidget } from '../../template';
import stixCoreObjectsAttributesQuery from './stixCoreObjectsAttributesQuery';

const fetchAttributeFromData = (stixCoreObject, splittedAttribute: string[]) => {
  if (splittedAttribute.length === 1) {
    return stixCoreObject?.[splittedAttribute[0]];
  }
  const subObject = stixCoreObject?.[splittedAttribute[0]];
  return Array.isArray(subObject)
    ? subObject.map((o) => fetchAttributeFromData(o, splittedAttribute.slice(1)))
    : fetchAttributeFromData(subObject, splittedAttribute.slice(1));
};

const buildAttributesOutcome = async (containerId: string, templateWidgets: TemplateWidget[]) => {
  if (templateWidgets.some((w) => w.widget.dataSelection[0].instance_id !== 'CONTAINER_ID')) {
    throw Error('The attribute widget should refers to the container');
  }
  const widgetsInfo = templateWidgets.map((w) => ({
    variableName: w.name,
    attribute: w.widget.dataSelection[0].columns[0].attribute,
    displayStyle: w.widget.dataSelection[0].columns[0].displayStyle,
  }));
  const data = await fetchQuery(stixCoreObjectsAttributesQuery, { id: containerId }).toPromise() as StixCoreObjectsAttributesQuery$data;
  const attributeWidgetsOutcome = widgetsInfo.map((col) => {
    const splittedAttribute = col.attribute.split('.');
    const result = fetchAttributeFromData(data.stixCoreObject, splittedAttribute);
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
