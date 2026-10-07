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
  // Sections of the latest Case Autopilot investigation of a case.
  ...['executive_summary', 'report', 'timeline', 'hypotheses', 'recommendations', 'iocs']
    .map((section) => `latestInvestigationRun.report_sections.${section}`),
];

const DATE_ATTRIBUTES = ['latestInvestigationRun.completed_at'];

// What a Case Autopilot investigation copied from its engine is text: only its report sections render, as sanitized
// Markdown (above), and the investigation as a whole, its sections together or any other value of it are escaped.
const INVESTIGATION_RUN_ATTRIBUTE = 'latestInvestigationRun';
const ESCAPED_TEXT = 'escaped-text';
const isInvestigationRunAttribute = (attribute: string) => attribute === INVESTIGATION_RUN_ATTRIBUTE
  || attribute.startsWith(`${INVESTIGATION_RUN_ATTRIBUTE}.`);
const escapeHtml = (text: string) => text
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll('\'', '&#39;');

// insertedAsHtml: the attribute outcome inserts the string into the document as is; a table cell or a list item is a
// React text node, escaped when rendered.
const buildStringAttribute = (inputValue: unknown, attributeType?: string, inTable = false, insertedAsHtml = !inTable) => {
  let value: string | ReactElement = typeof inputValue === 'string' ? inputValue : JSON.stringify(inputValue);

  if (attributeType === 'date') {
    // A missing date, such as the completion of an investigation still running, exports as an empty value.
    const date = new Date(value);
    value = Number.isNaN(date.getTime()) ? '' : dateFormat(date) ?? '';
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
  } else {
    if (inTable) {
      value = stringWithZeroWidthSpace(value);
    }
    if (attributeType === ESCAPED_TEXT && insertedAsHtml && typeof value === 'string') {
      value = escapeHtml(value);
    }
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
      if (isInvestigationRunAttribute(attribute)) attributeType = ESCAPED_TEXT;
      if (MARKDOWN_ATTRIBUTES.includes(attribute)) attributeType = 'markdown';
      if (DATE_ATTRIBUTES.includes(attribute)) attributeType = 'date';
    }

    let readableAttribute;
    if (Array.isArray(attributeData)) {
      if (displayStyle && displayStyle === 'list') {
        readableAttribute = renderToString(
          <ul>
            {attributeData.map((el) => (
              <li key={el}>{buildStringAttribute(el, attributeType, inTable, false)}</li>
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
