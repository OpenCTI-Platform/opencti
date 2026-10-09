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

  it('removes values loading a resource and border images', () => {
    const { container } = render(
      <HtmlDisplay content={'<p style="background-image: url(https://example.com/pixel.png); list-style-image: image-set(\'https://example.com/pixel.png\' 1x); border-image-source: linear-gradient(red, blue); background-color: yellow;">test</p>'} />,
    );
    const paragraph = container.querySelector('p');

    expect(paragraph?.style.getPropertyValue('background-image')).toBe('');
    expect(paragraph?.style.getPropertyValue('list-style-image')).toBe('');
    expect(paragraph?.style.getPropertyValue('border-image-source')).toBe('');
    expect(paragraph?.style.getPropertyValue('background-color')).toBe('yellow');
  });

  it('keeps the table cell styles produced by the rich-text editor', () => {
    const { container } = render(
      <HtmlDisplay content={'<table><tbody><tr><td style="background-color: rgb(217, 226, 243); border-top: 1pt solid currentcolor; border-left: none; width: 120px;" data-cell-background="light">a</td></tr></tbody></table>'} />,
    );
    const cell = container.querySelector('td');

    expect(cell?.style.getPropertyValue('background-color')).toBe('rgb(217, 226, 243)');
    expect(cell?.style.getPropertyValue('border-top-style')).toBe('solid');
    expect(cell?.style.getPropertyValue('border-left-style')).toBe('none');
    expect(cell?.style.getPropertyValue('width')).toBe('120px');
    expect(cell?.getAttribute('data-cell-background')).toBe('light');
  });

  it('contains the content within its container', () => {
    const { container } = render(
      <HtmlDisplay content={'<p style="transform: translate(-500px, -500px); margin-left: 40px;">test</p>'} />,
    );
    const wrapper = container.querySelector('.rich-text-content') as HTMLElement;

    expect(wrapper.style.getPropertyValue('contain')).toBe('paint');
    expect(container.querySelector('p')?.style.getPropertyValue('margin-left')).toBe('40px');
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

  it('does not change the behavior of the shared DOMPurify instance', () => {
    render(<HtmlDisplay content="<p>test</p>" />);

    expect(purify.sanitize('<p style="position: fixed;">a</p>')).toBe('<p style="position: fixed;">a</p>');
  });
});
