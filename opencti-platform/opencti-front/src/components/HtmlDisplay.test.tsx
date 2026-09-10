import { describe, expect, it } from 'vitest';
import { render } from '@testing-library/react';
import HtmlDisplay from './HtmlDisplay';

describe('HtmlDisplay style sanitization', () => {
  it('removes forbidden positioning properties while keeping safe styles', () => {
    const { container } = render(
      <HtmlDisplay content={'<p style="position: fixed; top: 0; left: 0; z-index: 9999; color: red; text-align: center;">test</p>'} />,
    );
    const paragraph = container.querySelector('p');

    expect(paragraph).toBeInTheDocument();
    expect(paragraph?.style.getPropertyValue('position')).toBe('');
    expect(paragraph?.style.getPropertyValue('top')).toBe('');
    expect(paragraph?.style.getPropertyValue('left')).toBe('');
    expect(paragraph?.style.getPropertyValue('z-index')).toBe('');
    expect(paragraph?.style.getPropertyValue('color')).toBe('red');
    expect(paragraph?.style.getPropertyValue('text-align')).toBe('center');
  });

  it('removes escaped forbidden property names while preserving allowed ones', () => {
    const { container } = render(
      <HtmlDisplay content={'<p style="po\\73ition: fixed; bottom: 0; color: green; font-weight: 700;">test</p>'} />,
    );
    const paragraph = container.querySelector('p');

    expect(paragraph).toBeInTheDocument();
    expect(paragraph?.style.getPropertyValue('position')).toBe('');
    expect(paragraph?.style.getPropertyValue('bottom')).toBe('');
    expect(paragraph?.style.getPropertyValue('color')).toBe('green');
    expect(paragraph?.style.getPropertyValue('font-weight')).toBe('700');
  });

  it('keeps style values containing semicolons and still removes forbidden properties', () => {
    const { container } = render(
      <HtmlDisplay content={'<p style="background-image: url(\'data:image/svg+xml;utf8,<svg xmlns=%22http://www.w3.org/2000/svg%22></svg>\'); right: 12px; color: blue;">test</p>'} />,
    );
    const paragraph = container.querySelector('p');

    expect(paragraph).toBeInTheDocument();
    expect(paragraph?.style.getPropertyValue('right')).toBe('');
    expect(paragraph?.style.getPropertyValue('color')).toBe('blue');
    expect(paragraph?.style.getPropertyValue('background-image')).toContain('data:image/svg+xml;utf8');
  });
});
