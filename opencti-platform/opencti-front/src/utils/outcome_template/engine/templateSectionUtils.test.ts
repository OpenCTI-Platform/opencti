import { describe, expect, it } from 'vitest';
import { buildTemplateContentWithOptionalSectionPruning, isSemanticallyEmptyHtmlFragment, parseHtmlInInertDocument } from './templateSectionUtils';

describe('templateSectionUtils', () => {
  it('should preserve empty placeholders within retained sections and before the first heading', () => {
    const content = buildTemplateContentWithOptionalSectionPruning(
      '<div><p>$empty</p><h2>Keep</h2><table><tbody><tr><td>Label</td><td>$empty</td></tr></tbody></table><p>$full</p></div>',
      [
        { variableName: 'empty', replacement: '', isEmpty: true, replaceAll: true },
        { variableName: 'full', replacement: 'Filled', isEmpty: false },
      ],
      { removeEmptySections: true },
    );

    expect(content).toEqual('<div><p></p><h2>Keep</h2><table><tbody><tr><td>Label</td><td></td></tr></tbody></table><p>Filled</p></div>');
  });

  it('should remove all section content up to the next equal heading across wrappers', () => {
    const content = buildTemplateContentWithOptionalSectionPruning(
      '<main><div><h2>Empty</h2><p>$empty</p></div><p>Fixed text</p><div class="page-break"></div><h2>Keep</h2><p>Static</p></main>',
      [{ variableName: 'empty', replacement: '', isEmpty: true }],
      { removeEmptySections: true },
    );

    expect(content).toEqual('<main><h2>Keep</h2><p>Static</p></main>');
  });

  it('should recognize standalone SVG as meaningful media', () => {
    expect(isSemanticallyEmptyHtmlFragment('<svg><circle r="10"></circle></svg>')).toBe(false);
  });

  it('should resolve and retain hyphenated variable names', () => {
    const content = buildTemplateContentWithOptionalSectionPruning(
      '<div><h2>Keep</h2><p>$foo-bar</p></div>',
      [{ variableName: 'foo-bar', replacement: 'Filled', isEmpty: false }],
      { removeEmptySections: true },
    );

    expect(content).toEqual('<div><h2>Keep</h2><p>Filled</p></div>');
  });

  it('should keep pre-heading text and treat h4 content as part of its h3 section', () => {
    const content = buildTemplateContentWithOptionalSectionPruning(
      '<main><p>Preamble</p><h3>Empty</h3><h4>$empty</h4><h3>Keep</h3><p>Static</p></main>',
      [{ variableName: 'empty', replacement: '', isEmpty: true }],
      { removeEmptySections: true },
    );

    expect(content).toEqual('<main><p>Preamble</p><h3>Keep</h3><p>Static</p></main>');
  });

  it('should treat whitespace-only rich text as empty and 0 false images as meaningful', () => {
    expect(isSemanticallyEmptyHtmlFragment('')).toEqual(true);
    expect(isSemanticallyEmptyHtmlFragment('&nbsp;')).toEqual(true);
    expect(isSemanticallyEmptyHtmlFragment('<div><p><br></p></div>')).toEqual(true);
    expect(isSemanticallyEmptyHtmlFragment('0')).toEqual(false);
    expect(isSemanticallyEmptyHtmlFragment('false')).toEqual(false);
    expect(isSemanticallyEmptyHtmlFragment('<img src="data:image/png;base64,abc" />')).toEqual(false);
  });

  it('should prune an empty section without deleting the next kept section in a shared ancestor', () => {
    const content = buildTemplateContentWithOptionalSectionPruning(
      '<div><div><h3>Empty</h3></div><p>$empty</p><div><h3>Next</h3></div><p>$full</p></div>',
      [
        { variableName: 'empty', replacement: '', isEmpty: true },
        { variableName: 'full', replacement: 'Filled', isEmpty: false },
      ],
      { removeEmptySections: true },
    );

    expect(content).toEqual('<div><div><h3>Next</h3></div><p>Filled</p></div>');
  });

  it('should preserve retained media line breaks and page breaks in kept content', () => {
    const content = buildTemplateContentWithOptionalSectionPruning(
      '<div><h1>Keep</h1><p>$full</p><img src="data:image/png;base64,abc" /><p><br></p><hr><span class="page-break"></span><div class="page-break"></div></div>',
      [{ variableName: 'full', replacement: 'Filled', isEmpty: false }],
      { removeEmptySections: true },
    );

    expect(content).toEqual('<div><h1>Keep</h1><p>Filled</p><img src="data:image/png;base64,abc"><p><br></p><hr><span class="page-break"></span><div class="page-break"></div></div>');
  });

  it('should treat headings globally and prune an empty wrapped section before a kept wrapped heading', () => {
    const content = buildTemplateContentWithOptionalSectionPruning(
      '<div><section><div><h1>Empty</h1></div><p>$empty</p></section><section><div><h1>Keep</h1></div><p>$full</p></section></div>',
      [
        { variableName: 'empty', replacement: '', isEmpty: true },
        { variableName: 'full', replacement: 'Body', isEmpty: false },
      ],
      { removeEmptySections: true },
    );

    expect(content).toEqual('<div><section><div><h1>Keep</h1></div><p>Body</p></section></div>');
  });
  it('should parse HTML in a document without browsing context so handlers never run', async () => {
    const container = parseHtmlInInertDocument('<img src="x" onerror="window.__xss = true">');
    expect(container.ownerDocument).not.toBe(document);
    expect(container.ownerDocument.defaultView).toBeNull();

    expect(isSemanticallyEmptyHtmlFragment('<img src="x" onerror="window.__xss = true">')).toEqual(false);
    await new Promise((resolve) => { setTimeout(resolve, 0); });
    expect((window as unknown as { __xss?: boolean }).__xss).toBeUndefined();
  });

  it('should match the longest known variable name so adjacent variables split on hyphens', () => {
    const content = buildTemplateContentWithOptionalSectionPruning(
      '<div><h2>Keep</h2><p>$first-$last</p></div>',
      [
        { variableName: 'first', replacement: 'A', isEmpty: false },
        { variableName: 'last', replacement: 'B', isEmpty: false },
      ],
      { removeEmptySections: true },
    );

    expect(content).toEqual('<div><h2>Keep</h2><p>A-B</p></div>');
  });

  it('should treat dollar text that is not a template variable as prose', () => {
    const content = buildTemplateContentWithOptionalSectionPruning(
      '<div><h2>Budget</h2><p>Budget: $5000 in $HOME</p><p>$empty</p><h2>Keep</h2><p>Price: $5000</p></div>',
      [{ variableName: 'empty', replacement: '', isEmpty: true }],
      { removeEmptySections: true },
    );

    expect(content).toEqual('<div><h2>Keep</h2><p>Price: $5000</p></div>');
  });

  it('should replace only the first occurrence of a variable unless replaceAll is set', () => {
    const content = buildTemplateContentWithOptionalSectionPruning(
      '<div><h2>Keep</h2><p>$list</p><p>$list</p><p>$attr $attr</p></div>',
      [
        { variableName: 'list', replacement: '<table></table>', isEmpty: false },
        { variableName: 'attr', replacement: 'value', isEmpty: false, replaceAll: true },
      ],
      { removeEmptySections: true },
    );

    expect(content).toEqual('<div><h2>Keep</h2><p><table></table></p><p>$list</p><p>value value</p></div>');
  });

  it('should drop a page break left at the end of the document by a removed trailing section', () => {
    const content = buildTemplateContentWithOptionalSectionPruning(
      '<div><h3>Keep</h3><p>$full</p><div class="page-break"><span>&nbsp;</span></div><h3>Empty</h3><p>$empty</p></div>',
      [
        { variableName: 'full', replacement: 'Filled', isEmpty: false },
        { variableName: 'empty', replacement: '', isEmpty: true },
      ],
      { removeEmptySections: true },
    );

    expect(content).toEqual('<div><h3>Keep</h3><p>Filled</p></div>');
  });

  it('should keep page breaks the template already ends with when nothing around them is pruned', () => {
    const content = buildTemplateContentWithOptionalSectionPruning(
      '<div><h3>Keep</h3><p>$full</p><div class="page-break"></div></div>',
      [{ variableName: 'full', replacement: 'Filled', isEmpty: false }],
      { removeEmptySections: true },
    );

    expect(content).toEqual('<div><h3>Keep</h3><p>Filled</p><div class="page-break"></div></div>');
  });
});
