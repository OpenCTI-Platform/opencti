import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import prepareMatrixCapture from './prepareMatrixCapture';

// jsdom does no layout: the scroll metrics are set by hand.
const setScrollMetrics = (element: HTMLElement, scrollWidth: number, clientWidth: number) => {
  Object.defineProperty(element, 'scrollWidth', { value: scrollWidth, configurable: true });
  Object.defineProperty(element, 'clientWidth', { value: clientWidth, configurable: true });
};

describe('prepareMatrixCapture', () => {
  let wrapper: HTMLElement;
  let scroller: HTMLElement;
  let plainBox: HTMLElement;

  beforeEach(() => {
    wrapper = document.createElement('div');
    wrapper.setAttribute('style', 'padding: 16px');
    scroller = document.createElement('div');
    scroller.setAttribute('style', 'overflow-x: auto; width: 800px; height: 600px');
    plainBox = document.createElement('div');
    plainBox.setAttribute('style', 'width: 50px');
    scroller.appendChild(document.createElement('span'));
    wrapper.append(scroller, plainBox);
    document.body.appendChild(wrapper);
    setScrollMetrics(scroller, 2400, 800);
  });

  afterEach(() => {
    wrapper.remove();
  });

  it('sets the wrapper to max-content wide so no column is cropped', () => {
    prepareMatrixCapture(wrapper);

    expect(wrapper.style.width).toBe('max-content');
    expect(wrapper.style.height).toBe('auto');
    // Its own style is kept.
    expect(wrapper.style.padding).toBe('16px');
  });

  it('opens a horizontal scroller to its whole scroll width', () => {
    prepareMatrixCapture(wrapper);

    expect(scroller.style.width).toBe('2400px');
    expect(scroller.style.height).toBe('auto');
    expect(scroller.style.overflow).toBe('visible');
  });

  it('leaves elements that do not scroll alone', () => {
    prepareMatrixCapture(wrapper);

    expect(plainBox.getAttribute('style')).toBe('width: 50px');
  });

  it('leaves a scroller whose content already fits alone', () => {
    setScrollMetrics(scroller, 800, 800);

    prepareMatrixCapture(wrapper);

    expect(scroller.getAttribute('style')).toBe('overflow-x: auto; width: 800px; height: 600px');
  });

  it('puts every inline style back when the capture is over', () => {
    const restore = prepareMatrixCapture(wrapper);
    restore();

    expect(wrapper.getAttribute('style')).toBe('padding: 16px');
    expect(scroller.getAttribute('style')).toBe('overflow-x: auto; width: 800px; height: 600px');
  });

  it('removes the style attribute of an element that had none', () => {
    wrapper.removeAttribute('style');

    const restore = prepareMatrixCapture(wrapper);
    expect(wrapper.hasAttribute('style')).toBe(true);
    restore();

    expect(wrapper.hasAttribute('style')).toBe(false);
  });
});
