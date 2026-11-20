import { afterEach, describe, expect, it } from 'vitest';
import { focusMainContent } from './focusMainContent';

const html = (content: string) => {
  document.body.innerHTML = `<input id="search" /><main tabindex="-1">${content}</main>`;
  document.getElementById('search')?.focus();
  return document.querySelector('main') as HTMLElement;
};
const target = '<span id="target" tabindex="-1" data-focus-target></span>';

describe('focusMainContent', () => {
  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('moves the focus from the active field to <main>', () => {
    const main = html('');
    focusMainContent();
    expect(document.activeElement).toBe(main);
  });

  it('prefers the focus target of the page', () => {
    html(target);
    focusMainContent();
    expect(document.activeElement).toBe(document.getElementById('target'));
  });

  it('keeps the focus on a click with a modifier (it opens a new tab)', () => {
    html(target);
    focusMainContent({ ctrlKey: true });
    expect(document.activeElement).toBe(document.getElementById('search'));
  });

  it('moves on to the target once a lazy page has rendered it', async () => {
    const main = html('');
    focusMainContent();
    expect(document.activeElement).toBe(main);

    main.insertAdjacentHTML('beforeend', target);
    await new Promise((resolve) => {
      setTimeout(resolve);
    });
    expect(document.activeElement).toBe(document.getElementById('target'));
  });

  it('falls back to <main> then the new target when the page left unmounts the focused target', async () => {
    const main = html(target);
    focusMainContent();
    expect(document.activeElement).toBe(document.getElementById('target'));

    main.innerHTML = '';
    await new Promise((resolve) => {
      setTimeout(resolve);
    });
    expect(document.activeElement).toBe(main);

    main.insertAdjacentHTML('beforeend', '<span id="next" tabindex="-1" data-focus-target></span>');
    await new Promise((resolve) => {
      setTimeout(resolve);
    });
    expect(document.activeElement).toBe(document.getElementById('next'));
  });

  it('does not steal the focus once the user moved it elsewhere', async () => {
    const main = html('<button id="other">Other</button>');
    focusMainContent();
    document.getElementById('other')?.focus();

    main.insertAdjacentHTML('beforeend', target);
    await new Promise((resolve) => {
      setTimeout(resolve);
    });
    expect(document.activeElement).toBe(document.getElementById('other'));
  });
});
