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
    expect(link.style.backgroundColor).toBe('var(--color-filigran-brand-primary-transparency)');
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
});
