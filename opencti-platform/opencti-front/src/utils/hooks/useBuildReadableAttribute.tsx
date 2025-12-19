import { renderToString } from 'react-dom/server';
import React, { ReactElement } from 'react';
import { marked } from 'marked';
import DOMPurify from 'dompurify';
import { dateFormat } from '../Time';
import { useBuildFilterKeysMapFromEntityType } from '../filters/filtersUtils';
import type { WidgetColumn } from '../widget/widget';
import { stringWithZeroWidthSpace } from '../String';

const MARKDOWN_ATTRIBUTES = [
  'description',
  'x_opencti_description',
  'representative.secondary',
  'attribute_abstract',
  'opinion',
  'explanation',
  'contact_information',
  'objective',
];

const buildStringAttribute = (inputValue: unknown, attributeType?: string, inTable = false) => {
  let value: string | ReactElement = typeof inputValue === 'string' ? inputValue : JSON.stringify(inputValue);

  if (attributeType === 'date') {
    value = dateFormat(new Date(value)) ?? '';
  } else if (attributeType === 'markdown') {
    const mark = marked.parse(value, {
      async: false,
      breaks: true,
      walkTokens: (token) => {
        if (token.type === 'text' && inTable) {
          token.text = stringWithZeroWidthSpace(token.text);
        }
      },
    });
    // !! Don't remove the call to sanitize, it's important to secure the call to dangerouslySetInnerHTML !!
    // We sanitize the given html above.
    const stringHtml = DOMPurify.sanitize(mark);
    value = <div dangerouslySetInnerHTML={{ __html: stringHtml }} />;
  } else if (inTable) {
    value = stringWithZeroWidthSpace(value);
  }
  return value;
};

const useBuildReadableAttribute = () => {
  const stixCoreObjectsAttributesMap = useBuildFilterKeysMapFromEntityType(['Stix-Core-Object']);

  const buildReadableAttribute = (attributeData: unknown, displayInfo: WidgetColumn, inTable = false) => {
    const { attribute, displayStyle } = displayInfo;
    let attributeType: string | undefined;
    if (attribute) {
      attributeType = stixCoreObjectsAttributesMap.get(attribute)?.type;
      if (MARKDOWN_ATTRIBUTES.includes(attribute)) attributeType = 'markdown';
    }

    let readableAttribute;
    if (Array.isArray(attributeData)) {
      if (displayStyle && displayStyle === 'list') {
        readableAttribute = renderToString(
          <ul>
            {attributeData.map((el) => (
              <li key={el}>{buildStringAttribute(el, attributeType, inTable)}</li>
            ))}
          </ul>,
        );
      } else {
        readableAttribute = attributeData.map((r) => buildStringAttribute(r, attributeType, inTable)).join(', ');
      }
    } else {
      readableAttribute = buildStringAttribute(attributeData, attributeType, inTable);
    }
    return readableAttribute;
  };

  return { buildReadableAttribute };
};

export default useBuildReadableAttribute;
