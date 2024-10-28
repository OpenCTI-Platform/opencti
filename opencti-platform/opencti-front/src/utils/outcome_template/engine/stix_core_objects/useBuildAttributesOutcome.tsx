import { renderToString } from 'react-dom/server';
import React from 'react';
import { fetchQuery } from '../../../../relay/environment';
import { StixCoreObjectsAttributesQuery$data } from './__generated__/StixCoreObjectsAttributesQuery.graphql';
import type { TemplateWidget } from '../../template';
import stixCoreObjectsAttributesQuery from './StixCoreObjectsAttributesQuery';
import getObjectProperty from '../../../object';
import { dateFormat, isDate } from '../../../Time';

const useBuildAttributesOutcome = () => {
  const buildAttributesOutcome = async (containerId: string, templateWidget: TemplateWidget) => {
    const instanceId = templateWidget.widget.dataSelection[0].instance_id;
    if (!instanceId) {
      throw Error('The attribute widget should refers to an instance');
    }
    const queryVariables = { id: instanceId === 'CONTAINER_ID' ? containerId : instanceId };
    const columns = templateWidget.widget.dataSelection[0].columns ?? [];
    const data = await fetchQuery(stixCoreObjectsAttributesQuery, queryVariables).toPromise() as StixCoreObjectsAttributesQuery$data;

    const format = (val: unknown) => {
      let value = typeof val === 'string' ? val : JSON.stringify(val);
      if (isDate(value)) value = dateFormat(new Date(value)) ?? '';
      return value;
    };

    return columns.map((col) => {
      const result = getObjectProperty(data.stixCoreObject ?? {}, col.attribute) ?? '';
      let attributeData: string;
      if (Array.isArray(result)) {
        if (col.displayStyle && col.displayStyle === 'list') {
          attributeData = renderToString(<ul>{result.map((el) => <li key={el}>{format(el)}</li>)}</ul>);
        } else {
          attributeData = result.map(format).join(', ');
        }
      } else {
        attributeData = format(result);
      }
      return {
        variableName: col.variableName,
        attributeData,
      };
    });
  };
  return { buildAttributesOutcome };
};

export default useBuildAttributesOutcome;
