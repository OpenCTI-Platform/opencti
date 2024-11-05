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

  const buildReadableAttribute = (attributeData: unknown, displayInfo: WidgetColumn) => {
    const { attribute, displayStyle } = displayInfo;
    let isDateAttribute = false;

    if (attribute) {
      const attributeDefinition = stixCoreObjectsAttributesMap.get(attribute);
      isDateAttribute = attributeDefinition?.type === 'date';
    }

    let readableAttribute;
    if (Array.isArray(attributeData)) {
      if (displayStyle && displayStyle === 'list') {
        readableAttribute = renderToString(
          <ul>
            {attributeData.map((el) => (
              <li key={el}>{buildStringAttribute(el, isDateAttribute)}</li>
            ))}
          </ul>,
        );
      } else {
        readableAttribute = attributeData.map((r) => buildStringAttribute(r, isDateAttribute)).join(', ');
      }
    } else {
      readableAttribute = buildStringAttribute(attributeData, isDateAttribute);
    }
    return readableAttribute;
  };

  return { buildReadableAttribute };
};

export default useBuildReadableAttribute;
