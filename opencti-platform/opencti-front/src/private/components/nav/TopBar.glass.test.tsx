import { readFileSync } from 'node:fs';
import path from 'node:path';
import React from 'react';
import { Header } from '@filigran/design-system';
import { describe, expect, it } from 'vitest';
import testRender from '../../../utils/tests/test-render';

/**
 * The fixed/glass doctrine of the bar, which regressed once with nothing to
 * catch it. It has three parts and each can break on its own:
 *
 *   1. the library paints the glass — a pin bump can drop it silently;
 *   2. the product positions the bar — the library never positions itself, so
 *      a lost `fixed` leaves the bar in the flow;
 *   3. the content scrolls UNDER the bar — the header inset has to be padding
 *      on the SCROLLING box. Put it on the wrapper above and the scroller
 *      starts below the bar: the glass survives every class assertion and has
 *      nothing left to blur, which is exactly how this went unnoticed.
 */

const read = (f: string) => readFileSync(path.resolve(f), 'utf8');

describe('the bar keeps its fixed/glass treatment', () => {
  it('the library still paints the glass on the Header we consume', () => {
    const { container } = testRender(<Header>bar</Header>);
    const root = container.firstElementChild as HTMLElement;
    // 94% over a 4px backdrop blur, on the root layer.
    expect(root.className).toContain('backdrop-blur-sm');
    expect(root.className).toContain('before:bg-gradient-default');
    expect(root.className).toContain('before:opacity-94');
  });

  it('the library does not position the bar, so the product must', () => {
    const root = testRender(<Header>bar</Header>).container.firstElementChild as HTMLElement;
    expect(root.className).not.toMatch(/(^|\s)(fixed|sticky|absolute)(\s|$)/);
    expect(read('src/private/components/nav/TopBar.tsx')).toMatch(/position:\s*'fixed'/);
  });

  it('the header inset sits on the scrolling box, so content travels under', () => {
    const source = read('src/private/Index.tsx');
    const mainSx = source.slice(source.indexOf('const mainSx'), source.indexOf('const boxSx'));
    const boxSx = source.slice(source.indexOf('const boxSx'));
    // The wrapper must not reserve the bar's height: that is what pushes the
    // scroller below the bar and kills the effect.
    expect(mainSx).not.toMatch(/paddingTop/);
    expect(boxSx).toMatch(/paddingTop:\s*headerInset/);
  });
});
