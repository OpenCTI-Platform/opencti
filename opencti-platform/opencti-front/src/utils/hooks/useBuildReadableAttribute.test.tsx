import { afterAll, beforeAll, describe, it, vi, expect } from 'vitest';
import React, { ReactElement } from 'react';
import { renderToString } from 'react-dom/server';
import * as filterUtils from '../filters/filtersUtils';
import { testRenderHook } from '../tests/test-render';
import useBuildReadableAttribute from './useBuildReadableAttribute';
import { FilterDefinition } from './useAuth';

describe('Hook: useBuildReadableAttribute', () => {
  beforeAll(() => {
    vi.spyOn(filterUtils, 'useBuildFilterKeysMapFromEntityType').mockImplementation(() => new Map([
      ['entity_type', { type: 'string' } as FilterDefinition],
      ['published', { type: 'date' } as FilterDefinition],
      ['revoked', { type: 'boolean' } as FilterDefinition],
      ['description', { type: 'text' } as FilterDefinition],
    ]));
  });
  afterAll(() => {
    vi.restoreAllMocks();
  });

  it('should display readable attribute', () => {
    const { hook } = testRenderHook(() => useBuildReadableAttribute());
    const { buildReadableAttribute } = hook.result.current;

    const stringAttribute = buildReadableAttribute('Report', { attribute: 'entity_type' });
    expect(stringAttribute).toEqual('Report');
    const dateAttribute = buildReadableAttribute('2024-11-07T14:42:41.000Z', { attribute: 'published' });
    expect(dateAttribute).toEqual('2024-11-07');
    const listAttribute = buildReadableAttribute(['label1', 'label2'], { attribute: 'objectLabel.value' });
    expect(listAttribute).toEqual('label1, label2');
    const listAttribute2 = buildReadableAttribute(['label1', 'label2'], { attribute: 'objectLabel.value', displayStyle: 'text' });
    expect(listAttribute2).toEqual('label1, label2');
    const emptyListAttribute = buildReadableAttribute([], { attribute: 'objectLabel.value', displayStyle: 'text' });
    expect(emptyListAttribute).toEqual('');
    const listAttributeWithChips = buildReadableAttribute(['label1', 'label2'], { attribute: 'objectLabel.value', displayStyle: 'list' });
    expect(listAttributeWithChips).toEqual('<ul><li>label1</li><li>label2</li></ul>');
    const emptyListAttributeWithChips = buildReadableAttribute([], { attribute: 'objectLabel.value', displayStyle: 'chip' });
    expect(emptyListAttributeWithChips).toEqual('');
    const nullAttribute = buildReadableAttribute(null, { attribute: 'objectLabel.value' });
    expect(nullAttribute).toEqual('null');
    const booleanAttribute = buildReadableAttribute(true, { attribute: 'revoked' });
    expect(booleanAttribute).toEqual('true');
  });
  it('should remove code bringing security issues like xss', () => {
    const { hook } = testRenderHook(() => useBuildReadableAttribute());
    const { buildReadableAttribute } = hook.result.current;

    const result = (<div dangerouslySetInnerHTML={{ __html: '<img src="x">' }} />);

    const textAttribute1 = buildReadableAttribute('<img src="x" onerror="alert(\'not happening\')">', { attribute: 'description' });
    expect(typeof textAttribute1).toEqual('object');
    expect(textAttribute1).toEqual(result);

    const textAttribute2 = buildReadableAttribute('<img src="x">', { attribute: 'description' });
    expect(typeof textAttribute2).toEqual('object');
    expect(textAttribute2).toEqual(result);
  });
  it('should render the Case Autopilot report sections as sanitized HTML and its completion as a date', () => {
    const { hook } = testRenderHook(() => useBuildReadableAttribute());
    const { buildReadableAttribute } = hook.result.current;

    const table = '| Rank | Candidate |\n| --- | --- |\n| 1 | APT28 <script>alert(1)</script> |';
    const section = buildReadableAttribute(table, { attribute: 'latestInvestigationRun.report_sections.hypotheses' }) as React.ReactElement<{ dangerouslySetInnerHTML: { __html: string } }>;
    const html = section.props.dangerouslySetInnerHTML.__html;
    expect(html).toContain('<table>');
    expect(html).toContain('<td>APT28 </td>');
    expect(html).not.toContain('<script>');
    expect(buildReadableAttribute('2026-10-03T18:00:00.000Z', { attribute: 'latestInvestigationRun.completed_at' })).toEqual('2026-10-03');
  });
  it('should escape every other value of the Case Autopilot investigation, never inserting it as HTML', () => {
    const { hook } = testRenderHook(() => useBuildReadableAttribute());
    const { buildReadableAttribute } = hook.result.current;

    const sections = { hypotheses: '<script>alert(1)</script>', report: '<img src="x" onerror="alert(1)">' };
    const whole = buildReadableAttribute({ report_sections: sections }, { attribute: 'latestInvestigationRun' }) as string;
    expect(whole).not.toContain('<script>');
    expect(whole).not.toContain('<img');
    expect(whole).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    const together = buildReadableAttribute(sections, { attribute: 'latestInvestigationRun.report_sections' }) as string;
    expect(together).not.toContain('<script>');
    expect(buildReadableAttribute(['<b>one</b>', 'two'], { attribute: 'latestInvestigationRun.steps' })).toEqual('&lt;b&gt;one&lt;/b&gt;, two');
    // A table cell or a list item is a text node escaped when rendered: escaped once, never twice
    const cell = renderToString(<td>{buildReadableAttribute('<b>one</b>', { attribute: 'latestInvestigationRun.summary' }, true)}</td>);
    expect(cell.replaceAll('\u200B', '')).toContain('&lt;b&gt;one&lt;/b&gt;');
    const list = buildReadableAttribute(['<b>one</b>'], { attribute: 'latestInvestigationRun.steps', displayStyle: 'list' });
    expect(list).toEqual('<ul><li>&lt;b&gt;one&lt;/b&gt;</li></ul>');
  });
  it('should export a missing date as an empty value', () => {
    const { hook } = testRenderHook(() => useBuildReadableAttribute());
    const { buildReadableAttribute } = hook.result.current;

    expect(buildReadableAttribute('', { attribute: 'latestInvestigationRun.completed_at' })).toEqual('');
    expect(buildReadableAttribute(null, { attribute: 'latestInvestigationRun.completed_at' })).toEqual('');
    expect(buildReadableAttribute(undefined, { attribute: 'published' })).toEqual('');
  });
  it('should keep the content used as representative.secondary as html', () => {
    const { hook } = testRenderHook(() => useBuildReadableAttribute());
    const { buildReadableAttribute } = hook.result.current;
    // Word gives pictures an alternative text with a blank line, which ends an html block in markdown.
    const content = '<p>Intro</p><p><img src="data:image/png;base64,AAAA" alt="A shield\n\nDescription automatically generated" width="373"></p><p>**not markdown**</p>';

    const html = renderToString(buildReadableAttribute(content, { attribute: 'representative.secondary' }) as ReactElement);
    expect(html).not.toContain('&lt;img');
    expect(html).toContain('<img src="data:image/png;base64,AAAA" alt="A shield\n\nDescription automatically generated" width="373">');
    expect(html).toContain('<p>**not markdown**</p>');

    const unsafe = renderToString(buildReadableAttribute('<p><img src="x" onerror="alert(\'not happening\')"></p>', { attribute: 'representative.secondary' }) as ReactElement);
    expect(unsafe).toContain('<img src="x">');
    expect(unsafe).not.toContain('onerror');
  });
  it('should keep rendering a markdown description used as representative.secondary', () => {
    const { hook } = testRenderHook(() => useBuildReadableAttribute());
    const { buildReadableAttribute } = hook.result.current;

    const markdown = renderToString(buildReadableAttribute('**Bold** text', { attribute: 'representative.secondary' }) as ReactElement);
    expect(markdown).toContain('<strong>Bold</strong> text');
    const markdownStartingWithHtml = renderToString(buildReadableAttribute('<b>Title</b> and **bold**', { attribute: 'representative.secondary' }) as ReactElement);
    expect(markdownStartingWithHtml).toContain('<strong>bold</strong>');
    // Autolinks are read as unknown elements by the html parser: they must stay markdown.
    const urlAutolink = renderToString(buildReadableAttribute('<https://example.com>', { attribute: 'representative.secondary' }) as ReactElement);
    expect(urlAutolink).toContain('<a href="https://example.com">https://example.com</a>');
    const emailAutolink = renderToString(buildReadableAttribute('<analyst@example.com>', { attribute: 'representative.secondary' }) as ReactElement);
    expect(emailAutolink).toContain('href="mailto:analyst@example.com"');
    expect(emailAutolink).toContain('analyst@example.com</a>');
    // A wrapper div around markdown (GitHub README style) must not be taken for rich text html.
    const wrapperDiv = renderToString(buildReadableAttribute('<div align="center">\n\n**Bold** and [link](https://x.io)\n\n</div>', { attribute: 'representative.secondary' }) as ReactElement);
    expect(wrapperDiv).toContain('<strong>Bold</strong>');
    expect(wrapperDiv).toContain('<a href="https://x.io">link</a>');
    const nestedWrapperDiv = renderToString(buildReadableAttribute('<div align="center"><div>\n\n**Bold** and [link](https://x.io)\n\n</div></div>', { attribute: 'representative.secondary' }) as ReactElement);
    expect(nestedWrapperDiv).toContain('<strong>Bold</strong>');
    expect(nestedWrapperDiv).toContain('<a href="https://x.io">link</a>');
  });
  it('should render markdown links as plain text only in tables', () => {
    const { hook } = testRenderHook(() => useBuildReadableAttribute());
    const { buildReadableAttribute } = hook.result.current;
    const description = 'Visit www.example.com, mail foo@example.com, read [the doc](https://doc.example.com) or <a href="https://raw.example.com">the raw link</a>';

    const inTable = renderToString(buildReadableAttribute(description, { attribute: 'description' }, true) as ReactElement);
    expect(inTable).not.toContain('<a');
    expect(inTable.replaceAll('\u200B', '')).toContain('Visit www.example.com, mail foo@example.com, read the doc or the raw link');

    const outsideTable = renderToString(buildReadableAttribute(description, { attribute: 'description' }) as ReactElement);
    expect(outsideTable).toContain('<a href="http://www.example.com">');
    expect(outsideTable).toContain('<a href="https://doc.example.com">');
    expect(outsideTable).toContain('<a href="https://raw.example.com">');
  });
});
