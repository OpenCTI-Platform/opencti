import { renderToString } from 'react-dom/server';
import React from 'react';
import { dateFormat } from '../Time';
import { useBuildFilterKeysMapFromEntityType } from '../filters/filtersUtils';
import type { WidgetColumn } from '../widget/widget';

const buildStringAttribute = (val: unknown, isDateAttribute: boolean) => {
  let value = typeof val === 'string' ? val : JSON.stringify(val);
  if (isDateAttribute) value = dateFormat(new Date(value)) ?? '';
  return value;
};

const useBuildReadableAttribute = () => {
  const stixCoreObjectsAttributesMap = useBuildFilterKeysMapFromEntityType(['Stix-Core-Object']);
  const buildReadableAttribute = (result: unknown, displayInfo: WidgetColumn) => {
    const { attribute } = displayInfo;
    let isDateAttribute = false;
    if (attribute) {
      const attributeDefinition = stixCoreObjectsAttributesMap.get(attribute);
      isDateAttribute = attributeDefinition?.type === 'date';
    }

    let attributeData;
    if (Array.isArray(result)) {
      if (displayInfo.displayStyle && displayInfo.displayStyle === 'list') {
        attributeData = renderToString(<ul>{result.map((el) => <li key={el}>{buildStringAttribute(el, isDateAttribute)}</li>)}</ul>);
      } else {
        attributeData = result.map((r) => buildStringAttribute(r, isDateAttribute)).join(', ');
      }
    } else {
      attributeData = buildStringAttribute(result, isDateAttribute);
    }
    return attributeData;
  };
  return { buildReadableAttribute };
};

export default useBuildReadableAttribute;
