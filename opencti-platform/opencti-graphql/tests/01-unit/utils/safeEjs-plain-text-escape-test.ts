import { describe, expect, it } from 'vitest';
import { safeRender } from '../../../src/utils/safeEjs.client';

describe('safeRender usePlainTextEscape option', () => {
  it('does not HTML-escape <%= %> with usePlainTextEscape', async () => {
    const out = await safeRender('<%= name %>|<%= missing %>', { name: 'L\'APT & <b>', missing: undefined }, { usePlainTextEscape: true });
    expect(out).toBe('L\'APT & <b>|');
  });

  it('still HTML-escapes by default', async () => {
    expect(await safeRender('<%= name %>', { name: 'L\'APT &' })).toBe('L&#39;APT &amp;');
  });
});
