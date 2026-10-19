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

// representative.secondary falls back to the content of the entity (HTML from the rich text editor)
// when there is no description. This HTML must not be parsed as markdown: a blank line inside a tag,
// as in the alternative text Word gives to pictures, ends the HTML block and the rest of the tag is escaped.
// The rich text editor only writes block elements at the top level: anything else (text, inline tags,
// markdown autolinks like <https://example.com> that the parser reads as unknown elements) is markdown.
const RICH_TEXT_BLOCK_TAGS = new Set(['P', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'UL', 'OL', 'TABLE', 'BLOCKQUOTE', 'PRE', 'FIGURE', 'DIV', 'HR', 'IMG']);
const isRichTextHtml = (value: string) => {
  const { body } = new DOMParser().parseFromString(value, 'text/html');
  const nodes = Array.from(body.childNodes).filter((node) => node.nodeType !== Node.TEXT_NODE || node.textContent?.trim());
  return nodes.length > 0 && nodes.every((node) => node instanceof Element && RICH_TEXT_BLOCK_TAGS.has(node.tagName));
};

const buildStringAttribute = (inputValue: unknown, attributeType?: string, inTable = false) => {
  let value: string | ReactElement = typeof inputValue === 'string' ? inputValue : JSON.stringify(inputValue);

  if (attributeType === 'html') {
    // !! Don't remove the call to sanitize, it's important to secure the call to dangerouslySetInnerHTML !!
    const stringHtml = DOMPurify.sanitize(value, inTable ? { FORBID_TAGS: ['a'] } : undefined);
    value = <div dangerouslySetInnerHTML={{ __html: stringHtml }} />;
  } else if (attributeType === 'date') {
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
    // In tables, the only link wanted is the one to the entity page: other links
    // (markdown, auto-detected like www.example.com, or raw HTML) are unwrapped, their text is kept.
    const stringHtml = DOMPurify.sanitize(mark, inTable ? { FORBID_TAGS: ['a'] } : undefined);
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
      if (attribute === 'representative.secondary' && typeof attributeData === 'string' && isRichTextHtml(attributeData)) {
        attributeType = 'html';
      }
    }
    // Attributes unknown to the standard schema (e.g. custom fields) carry their own
    // attributeType directly on the column: use it as a fallback.
    if (!attributeType && displayInfo.attributeType) {
      attributeType = displayInfo.attributeType;
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
