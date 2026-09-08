import React from 'react';
import { describe, expect, it, vi, afterEach } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../utils/tests/test-render';
import Breadcrumbs from './Breadcrumbs';

const PATH = [
  { label: 'Entities' },
  { label: 'Sectors', link: '/dashboard/entities/sectors' },
  { label: 'Nuclear power plant operators of the Rhone valley', current: true },
];

afterEach(() => {
  vi.restoreAllMocks();
});

describe('Breadcrumbs', () => {
  it('is a named navigation landmark holding an ordered list', () => {
    testRender(<Breadcrumbs elements={PATH} />);
    const nav = screen.getByRole('navigation', { name: 'Breadcrumb' });
    expect(nav.tagName).toBe('NAV');
    expect(nav.querySelector('ol')).not.toBeNull();
  });

  it('marks the page the user is on, which nothing did before', () => {
    testRender(<Breadcrumbs elements={PATH} />);
    const current = screen.getByText(PATH[2].label);
    expect(current).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('navigation').querySelectorAll('[aria-current]')).toHaveLength(1);
  });

  it('keeps the whole label in the DOM and in title, instead of cutting it', () => {
    testRender(<Breadcrumbs elements={PATH} />);
    const current = screen.getByText(PATH[2].label);
    expect(current.textContent).toBe(PATH[2].label);
    expect(current).toHaveAttribute('title', PATH[2].label);
    expect(screen.getByText('Sectors')).toHaveAttribute('title', 'Sectors');
    expect(screen.getByRole('navigation').textContent).not.toContain('...');
  });

  it('takes an ancestor destination through `to`, so the router keeps the click', () => {
    testRender(<Breadcrumbs elements={PATH} />);
    const link = screen.getByRole('link', { name: 'Sectors' });
    // `href` through a react-router Link is REPLACED by the current location:
    // a focusable link back to the page you are already on.
    expect(link).toHaveAttribute('href', '/dashboard/entities/sectors');
  });

  it('emits no design-system prop-contract warning', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    testRender(<Breadcrumbs elements={PATH} />);
    const breadcrumbWarnings = warn.mock.calls
      .map((args) => String(args[0]))
      .filter((message) => message.startsWith('Breadcrumbs:'));
    expect(breadcrumbWarnings).toEqual([]);
  });

  it('hides every separator from assistive technology but keeps it a text node', () => {
    testRender(<Breadcrumbs elements={PATH} />);
    const separators = screen.getByRole('list').querySelectorAll('[aria-hidden="true"]');
    expect(separators).toHaveLength(PATH.length - 1);
    for (const separator of separators) expect(separator.textContent).toBe('/');
  });

  it('reads as the labels joined by the separator, which an e2e page model asserts', () => {
    testRender(<Breadcrumbs elements={PATH} />);
    // tests_e2e/model/menu/leftBar.pageModel.ts expectBreadcrumb() looks the
    // visible path up as `items.join('/')`.
    expect(screen.getByRole('list').textContent).toBe(PATH.map((e) => e.label).join('/'));
  });

  it('keeps the two DOM hooks this repository reads', () => {
    testRender(<Breadcrumbs elements={PATH} />);
    const nav = screen.getByRole('navigation');
    // dataGrid/components/DataTableBody.tsx keys a table height on the id.
    expect(nav).toHaveAttribute('id', 'page-breadcrumb');
    expect(nav).toHaveAttribute('data-testid', 'navigation');
  });

  it('puts the bottom margin on the landmark, and drops it for noMargin', () => {
    const { unmount } = testRender(<Breadcrumbs elements={PATH} />);
    expect(screen.getByRole('navigation').className).toContain('mb-2');
    unmount();
    testRender(<Breadcrumbs elements={PATH} noMargin />);
    expect(screen.getByRole('navigation').className).not.toContain('mb-2');
  });

  it('puts the sensitive-zone chip in the adornment slot: inside the landmark, outside the list', () => {
    testRender(<Breadcrumbs elements={PATH} isSensitive />);
    const nav = screen.getByRole('navigation');
    const list = screen.getByRole('list');
    const chip = screen.getByText('Danger Zone');
    expect(nav.contains(chip)).toBe(true);
    // Outside the list — it is not a step of the path, so it is not an <li>
    // and assistive technology never announces it as one.
    expect(list.contains(chip)).toBe(false);
    expect(chip.closest('li')).toBeNull();
  });

  it('forwards a host adornment to the same slot', () => {
    testRender(
      <Breadcrumbs elements={PATH} adornment={<span data-testid="info-icon">i</span>} />,
    );
    const nav = screen.getByRole('navigation');
    const icon = screen.getByTestId('info-icon');
    expect(nav.contains(icon)).toBe(true);
    expect(screen.getByRole('list').contains(icon)).toBe(false);
  });

  it('keeps both when a sensitive page also passes an adornment', () => {
    testRender(
      <Breadcrumbs elements={PATH} isSensitive adornment={<span data-testid="info-icon">i</span>} />,
    );
    expect(screen.getByText('Danger Zone')).toBeInTheDocument();
    expect(screen.getByTestId('info-icon')).toBeInTheDocument();
  });
});
