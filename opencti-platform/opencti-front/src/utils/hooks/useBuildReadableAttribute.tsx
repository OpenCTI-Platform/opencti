import { renderToString } from 'react-dom/server';
import React, { ReactElement } from 'react';
import { dateFormat } from '../Time';
import { useBuildFilterKeysMapFromEntityType } from '../filters/filtersUtils';
import type { WidgetColumn } from '../widget/widget';
import MarkdownDisplay from '../../components/MarkdownDisplay';

const buildStringAttribute = (inputValue: unknown, attributeType?: string, inTable?: boolean) => {
  let value: string | ReactElement = typeof inputValue === 'string' ? inputValue : JSON.stringify(inputValue);
  if (attributeType) {
    if (attributeType === 'date') value = dateFormat(new Date(value)) ?? '';
    if (attributeType === 'text') {
      const valueInMarkdown = (<MarkdownDisplay
        content={value}
        remarkGfmPlugin
        commonmark
        disableWarningAtLinkClick
        emptyStringIfUndefined
                               />);
      value = inTable ? valueInMarkdown : renderToString(valueInMarkdown);
    }
  }
  return value;
};

const useBuildReadableAttribute = () => {
  const stixCoreObjectsAttributesMap = useBuildFilterKeysMapFromEntityType(['Stix-Core-Object']);

  const buildReadableAttribute = (attributeData: unknown, displayInfo: WidgetColumn, inTab = false) => {
    const { attribute, displayStyle } = displayInfo;
    const attributeType = attribute ? stixCoreObjectsAttributesMap.get(attribute)?.type : undefined;

    let readableAttribute;
    if (Array.isArray(attributeData)) {
      if (displayStyle && displayStyle === 'list') {
        readableAttribute = renderToString(
          <ul>
            {attributeData.map((el) => (
              <li key={el}>{buildStringAttribute(el, attributeType)}</li>
            ))}
          </ul>,
        );
      } else {
        readableAttribute = attributeData.map((r) => buildStringAttribute(r, attributeType)).join(', ');
      }
    } else {
      readableAttribute = buildStringAttribute(attributeData, attributeType, inTab);
    }
    return readableAttribute;
  };

  return { buildReadableAttribute };
};

export default useBuildReadableAttribute;
