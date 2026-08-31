import { screen } from '@testing-library/react';
import React from 'react';
import { describe, expect, it } from 'vitest';
import testRender from '../../../utils/tests/test-render';
import TopBarIconLink from './TopBarIconLink';

const renderLink = (active: boolean) => testRender(
  <TopBarIconLink
    aria-label="Notifications"
    to="/dashboard/profile/notifications/alerts"
    active={active}
    icon={<svg data-testid="glyph" />}
  />,
);

describe('TopBarIconLink', () => {
  it('is a real anchor, so middle-click and open-in-new-tab keep working', () => {
    renderLink(false);
    const link = screen.getByRole('link', { name: 'Notifications' });
    expect(link.tagName).toBe('A');
    expect(link).toHaveAttribute('href', '/dashboard/profile/notifications/alerts');
  });

  it('marks the current page and tints it from the library token', () => {
    renderLink(true);
    const link = screen.getByRole('link', { name: 'Notifications' });
    expect(link).toHaveAttribute('aria-current', 'page');
    // The token, never a literal: a hardcoded colour would not follow the theme.
    expect(link.style.backgroundColor).toBe('var(--color-filigran-brand-primary-transparency-10)');
  });

  it('leaves a non-current link untinted', () => {
    renderLink(false);
    const link = screen.getByRole('link', { name: 'Notifications' });
    expect(link).not.toHaveAttribute('aria-current');
    expect(link.style.backgroundColor).toBe('');
  });

  it('carries the library glyph colour, so it matches the IconButtons beside it', () => {
    renderLink(false);
    const link = screen.getByRole('link', { name: 'Notifications' });
    // Without this the link inherits the bar's text colour and reads white,
    // while the library IconButton next to it resolves the brand token.
    expect(link.style.color).toBe('var(--color-filigran-brand-primary)');
  });

  it('hides the glyph from assistive technology, as IconButton does', () => {
    renderLink(false);
    expect(screen.getByTestId('glyph').parentElement).toHaveAttribute('aria-hidden', 'true');
  });

  describe('the unread marker', () => {
    const renderBadged = (unread: number, invisible = false) => testRender(
      <TopBarIconLink
        aria-label="Notifications"
        to="/dashboard/profile/notifications/alerts"
        icon={<svg data-testid="glyph" />}
        badge={{ content: unread, dot: true, invisible, accessibleText: `${unread} unread` }}
      />,
    );

    it('announces the count as the control DESCRIPTION, computed, not as text in the tree', () => {
      renderBadged(3);
      const link = screen.getByRole('link', { name: 'Notifications' });
      // Computed through the accname/description algorithm — the same thing a screen reader resolves, and the
      // thing that was empty when the badge wrapped the aria-hidden glyph instead of the control.
      expect(link).toHaveAccessibleName('Notifications');
      expect(link).toHaveAccessibleDescription('3 unread');
    });

    it('leaves the control undescribed when there is nothing unread', () => {
      renderBadged(0, true);
      const link = screen.getByRole('link', { name: 'Notifications' });
      expect(link).toHaveAccessibleName('Notifications');
      expect(link).toHaveAccessibleDescription('');
    });

    it('keeps the marker out of the glyph, which no assistive technology reads', () => {
      renderBadged(3);
      const link = screen.getByRole('link', { name: 'Notifications' });
      const described = link.getAttribute('aria-describedby');
      expect(described).toBeTruthy();
      // The described node must not sit inside the hidden glyph span.
      const node = document.getElementById(described as string);
      expect(node).not.toBeNull();
      expect(node?.closest('[aria-hidden="true"]')).toBeNull();
    });
  });

  it('forwards the props asChild clones onto it, or the tooltip never opens', () => {
    const onPointerEnter = () => {};
    testRender(
      <TopBarIconLink
        aria-label="Triggers"
        to="/dashboard/profile/triggers"
        icon={<svg data-testid="glyph" />}
        data-state="closed"
        onPointerEnter={onPointerEnter}
      />,
    );
    // `data-state` is what Radix's trigger puts on its child; if the component
    // drops unknown props, it never lands and the tooltip is silently dead.
    expect(screen.getByRole('link', { name: 'Triggers' })).toHaveAttribute('data-state', 'closed');
  });

  it('keeps the library variant when a parent clones a className onto it', () => {
    const { rerender } = testRender(
      <TopBarIconLink
        aria-label="Triggers"
        to="/dashboard/profile/triggers"
        icon={<svg data-testid="glyph" />}
      />,
    );
    const variant = screen.getByRole('link', { name: 'Triggers' }).getAttribute('class');
    expect(variant).toBeTruthy();
    // Spreading an incoming className over the computed one erased the whole
    // variant and the control collapsed to its glyph — 24x28 instead of 36x36.
    rerender(
      <TopBarIconLink
        aria-label="Triggers"
        to="/dashboard/profile/triggers"
        icon={<svg data-testid="glyph" />}
        className="from-a-cloning-parent"
      />,
    );
    const merged = screen.getByRole('link', { name: 'Triggers' }).getAttribute('class') ?? '';
    expect(merged).toContain('from-a-cloning-parent');
    for (const cls of (variant as string).split(/\s+/)) expect(merged).toContain(cls);
  });
});
