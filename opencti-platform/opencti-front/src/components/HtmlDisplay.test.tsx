import { describe, expect, it } from 'vitest';
import { render } from '@testing-library/react';
import purify from 'dompurify';
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

  it('parses style values containing semicolons and still removes forbidden properties', () => {
    const { container } = render(
      <HtmlDisplay content={'<p style="background-image: url(\'data:image/svg+xml;utf8,<svg xmlns=%22http://www.w3.org/2000/svg%22></svg>\'); right: 12px; color: blue;">test</p>'} />,
    );
    const paragraph = container.querySelector('p');

    expect(paragraph).toBeInTheDocument();
    expect(paragraph?.style.getPropertyValue('right')).toBe('');
    expect(paragraph?.style.getPropertyValue('background-image')).toBe('');
    expect(paragraph?.style.getPropertyValue('color')).toBe('blue');
  });

  it('removes non-allowlisted properties and negative indentation', () => {
    const { container } = render(
      <HtmlDisplay content={'<p style="transform: scale(20); translate: -500px; margin-top: -2000px; margin-left: -100vw; font-size: 18px;">a</p><p style="margin-left: 40px;">b</p>'} />,
    );
    const [first, second] = Array.from(container.querySelectorAll('p'));

    expect(first.style.getPropertyValue('transform')).toBe('');
    expect(first.style.getPropertyValue('translate')).toBe('');
    expect(first.style.getPropertyValue('margin-top')).toBe('');
    expect(first.style.getPropertyValue('margin-left')).toBe('');
    expect(first.style.getPropertyValue('font-size')).toBe('18px');
    expect(second.style.getPropertyValue('margin-left')).toBe('40px');
  });

  it('removes style elements', () => {
    const { container } = render(
      <HtmlDisplay content="<p>test</p><style>p { color: red; }</style>" />,
    );

    expect(container.querySelector('p')).toBeInTheDocument();
    expect(container.querySelector('style')).not.toBeInTheDocument();
  });

  it('removes dialog elements and popover attributes', () => {
    const { container } = render(
      <HtmlDisplay content={'<dialog open>a</dialog><button popovertarget="p">b</button><div id="p" popover>c</div>'} />,
    );

    expect(container.querySelector('dialog')).not.toBeInTheDocument();
    expect(container.querySelector('[popover]')).not.toBeInTheDocument();
    expect(container.querySelector('[popovertarget]')).not.toBeInTheDocument();
  });

  it('keeps rich-text classes and removes other classes', () => {
    const { container } = render(
      <HtmlDisplay content={'<p><mark class="marker-yellow css-1abcd">a</mark></p><ul class="todo-list MuiDrawer-paper"><li>b</li></ul>'} />,
    );

    expect(container.querySelector('mark')?.className).toBe('marker-yellow');
    expect(container.querySelector('ul')?.className).toBe('todo-list');
  });

  it('does not change the behavior of the shared DOMPurify instance', () => {
    render(<HtmlDisplay content="<p>test</p>" />);

    expect(purify.sanitize('<p style="position: fixed;" class="custom">a</p>')).toBe('<p style="position: fixed;" class="custom">a</p>');
  });
});
