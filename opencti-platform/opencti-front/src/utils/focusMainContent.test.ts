import { afterEach, describe, expect, it } from 'vitest';
import { focusMainContent } from './focusMainContent';

describe('focusMainContent', () => {
  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('moves the focus from the active field to <main>', () => {
    document.body.innerHTML = '<input id="search" /><main tabindex="-1"></main>';
    document.getElementById('search')?.focus();
    focusMainContent();
    expect(document.activeElement).toBe(document.querySelector('main'));
  });

  it('keeps the focus on a click with a modifier (it opens a new tab)', () => {
    document.body.innerHTML = '<input id="search" /><main tabindex="-1"></main>';
    document.getElementById('search')?.focus();
    focusMainContent({ ctrlKey: true });
    expect(document.activeElement).toBe(document.getElementById('search'));
  });
});
