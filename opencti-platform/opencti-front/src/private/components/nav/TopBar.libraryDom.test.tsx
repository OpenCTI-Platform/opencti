import React from 'react';
import { describe, expect, it } from 'vitest';
import UploadImport from '../../../components/UploadImport';
import testRender from '../../../utils/tests/test-render';

/** The source guard next door says what the bar *imports*. */

/** MUI classes the rendered tree may still carry, and what retires each. */
const ALLOWED_RENDERED = {
  // Retired by: a library icon set covering the product's glyphs.
  MuiSvgIcon: 'glyph only — the library ships no icon set',
};

/** Every MUI class in a rendered tree, deduplicated by component family. */
const muiFamilies = (root: HTMLElement) => {
  const families = new Set<string>();
  for (const el of [root, ...Array.from(root.querySelectorAll('*'))]) {
    const cls = el.getAttribute?.('class');
    if (!cls) continue;
    for (const name of cls.split(/\s+/)) {
      const match = /^(Mui[A-Za-z]+)-/.exec(name);
      if (match) families.add(match[1]);
    }
  }
  return [...families].sort();
};

describe('the bar controls render as library components', () => {
  it.each([
    ['icon', 'icon' as const],
    ['text', 'contained' as const],
  ])('the import control renders no MUI component in its %s form', (_name, variant) => {
    const { baseElement } = testRender(<UploadImport variant={variant} />);
    // A control that failed to mount would pass every class assertion below.
    expect(baseElement.querySelector('button')).not.toBeNull();
    for (const family of muiFamilies(baseElement)) {
      expect(ALLOWED_RENDERED, `${family} is rendered and is not an allowed MUI family`)
        .toHaveProperty(family);
    }
  });

  it('the import control keeps its accessible name off the tooltip', () => {
    const { baseElement } = testRender(<UploadImport variant="icon" />);
    // The tooltip is hover-only; the name must survive without it.
    const button = baseElement.querySelector('button') as HTMLButtonElement;
    expect(button.getAttribute('aria-label')).toBeTruthy();
  });
});
