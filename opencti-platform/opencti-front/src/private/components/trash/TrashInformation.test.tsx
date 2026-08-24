/**
 * The breadcrumb adornment on the trash page must be reachable by keyboard.
 *
 * The library's `adornment` slot promises only a POSITION: "anything focusable
 * placed here comes after the last link in the tab order, so a tooltip attached
 * to it is reachable by keyboard, not only by pointer". Placing something
 * focusable there is the host's side of that contract, and this site placed a
 * bare `<svg>` — not focusable, no accessible name. Three sentences explaining
 * what the trash keeps and for how long were pointer-only.
 *
 * Focus is measured by really pressing Tab, never by calling focus(): a
 * programmatic focus reaches elements the keyboard cannot, which is exactly the
 * difference under test here.
 */
import React from 'react';
import { screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import testRender from '../../../utils/tests/test-render';
import Breadcrumbs from '../../../components/Breadcrumbs';
import TrashInformation from './TrashInformation';

const renderTrail = () => testRender(
  <Breadcrumbs
    elements={[
      { label: 'Data', link: '/dashboard/data' },
      { label: 'Trash', current: true },
    ]}
    adornment={<TrashInformation />}
  />,
);

describe('the trash breadcrumb adornment', () => {
  it('is reachable by pressing Tab, with an accessible name', async () => {
    const { user } = renderTrail();
    const link = screen.getByRole('link', { name: 'Data' });

    // Walk the tab order from the start of the document and collect what the
    // keyboard actually lands on, so the assertion is about reachability and
    // not about an element merely existing in the DOM.
    const reached: string[] = [];
    for (let step = 0; step < 4; step += 1) {
      await user.tab();
      const active = document.activeElement as HTMLElement | null;
      if (!active || active === document.body) break;
      reached.push(`${active.tagName.toLowerCase()}:${active.getAttribute('aria-label') ?? active.textContent ?? ''}`);
    }

    expect(reached[0]).toBe(`a:${link.textContent}`);
    expect(
      reached.length,
      'nothing after the last link takes focus — the adornment is pointer-only',
    ).toBeGreaterThan(1);
    expect(reached[1]).toMatch(/More information|Plus d/);
  });

  it('shows its explanation on focus, not only on hover', async () => {
    const { user } = renderTrail();
    await user.tab();
    await user.tab();
    expect(
      await screen.findByRole('tooltip'),
      'no tooltip opened on the keyboard path',
    ).toHaveTextContent(/manually deleted from the platform/);
  });
});
