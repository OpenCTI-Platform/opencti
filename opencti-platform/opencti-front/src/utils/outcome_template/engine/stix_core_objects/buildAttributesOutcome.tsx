import { renderToString } from 'react-dom/server';
import React from 'react';
import { fetchQuery } from '../../../../relay/environment';
import { StixCoreObjectsAttributesQuery$data } from './__generated__/StixCoreObjectsAttributesQuery.graphql';
import type { TemplateWidget } from '../../template';
import stixCoreObjectsAttributesQuery from './StixCoreObjectsAttributesQuery';
import getObjectProperty from '../../../object';

const buildAttributesOutcome = async (containerId: string, templateWidgets: TemplateWidget[]) => {
  if (templateWidgets.some((w) => w.widget.dataSelection[0].instance_id !== 'CONTAINER_ID')) {
    throw Error('The attribute widget should refers to the container');
  }
  const widgetsInfo = templateWidgets.map((w) => ({
    variableName: w.name,
    columns: w.widget.dataSelection[0].columns,
  }));
  const data = await fetchQuery(stixCoreObjectsAttributesQuery, { id: containerId }).toPromise() as StixCoreObjectsAttributesQuery$data;
  const attributeWidgetsOutcome = widgetsInfo.map(({ variableName, columns }) => {
    const attributesData = (columns ?? []).map((col) => {
      const result = getObjectProperty(data.stixCoreObject ?? {}, col.attribute);
      let attributeData;
      if (!Array.isArray(result)) {
        attributeData = result;
      } else if (col.displayStyle && col.displayStyle === 'list') {
        attributeData = renderToString(<ul>{result.map((el) => <li key={el}>{el}</li>)}</ul>);
      } else {
        attributeData = result.join(', ');
      }
      return attributeData;
    });
    return { variableName, attributeData: attributesData.length === 1 ? attributesData[0] : attributesData.join(', ') };
  });
  return attributeWidgetsOutcome;
};

export default buildAttributesOutcome;
