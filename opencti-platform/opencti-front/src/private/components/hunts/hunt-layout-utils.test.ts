import { afterEach, describe, expect, it, vi } from 'vitest';
import { unscrolledTop } from './hunt-layout-utils';

const scrolled = (element: HTMLElement, scrollTop: number) => {
  Object.defineProperty(element, 'scrollTop', { configurable: true, value: scrollTop });
};

describe('Hunt layout utils', () => {
  afterEach(() => {
    document.body.innerHTML = '';
    scrolled(document.documentElement, 0);
  });

  describe('unscrolledTop()', () => {
    it('should give the top of the element as long as nothing is scrolled', () => {
      const element = document.createElement('div');
      document.body.appendChild(element);
      vi.spyOn(element, 'getBoundingClientRect').mockReturnValue({ top: 240 } as DOMRect);
      expect(unscrolledTop(element)).toEqual(240);
    });

    it('should give the same top whichever ancestor is scrolled, the content box or the window', () => {
      const content = document.createElement('div');
      const element = document.createElement('div');
      content.appendChild(element);
      document.body.appendChild(content);
      scrolled(content, 300);
      vi.spyOn(element, 'getBoundingClientRect').mockReturnValue({ top: -60 } as DOMRect);
      expect(unscrolledTop(element)).toEqual(240);
      scrolled(content, 0);
      scrolled(document.documentElement, 100);
      vi.spyOn(element, 'getBoundingClientRect').mockReturnValue({ top: 140 } as DOMRect);
      expect(unscrolledTop(element)).toEqual(240);
    });
  });
});
