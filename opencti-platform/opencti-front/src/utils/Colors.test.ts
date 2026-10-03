import { describe, it, expect } from 'vitest';
import { hexToRGB, isWashVisibleOn } from './Colors';

describe('Function: hexToRGB', () => {
  it('should return matching rgb color', () => {
    expect(hexToRGB('#70D907', 1)).toEqual('rgb(112, 217, 7, 1)');
  });

  it('should return default alpha value', () => {
    expect(hexToRGB('#70D907')).toEqual('rgb(112, 217, 7, 0.1)');
  });
});

describe('Function: isWashVisibleOn', () => {
  // The surfaces the wash is painted on, light and dark.
  const LIGHT = '#f2f2f3';
  const DARK = '#070d18';

  it('keeps every coloured TLP level, in both themes', () => {
    for (const surface of [LIGHT, DARK]) {
      for (const color of ['#2e7d32', '#d84315', '#c62828']) {
        expect(isWashVisibleOn(color, surface)).toBe(true);
      }
    }
  });

  it('drops the seeded white of TLP:CLEAR on the light surface only', () => {
    expect(isWashVisibleOn('#ffffff', LIGHT)).toBe(false);
    // ...and keeps it where it can actually be seen.
    expect(isWashVisibleOn('#ffffff', DARK)).toBe(true);
  });

  it('drops any near-white an admin might choose', () => {
    expect(isWashVisibleOn('#fafafa', LIGHT)).toBe(false);
    expect(isWashVisibleOn('#fffde7', LIGHT)).toBe(false);
  });

  it('drops colours that vanish on the dark surface', () => {
    expect(isWashVisibleOn('#000000', DARK)).toBe(false);
    expect(isWashVisibleOn('#0b1020', DARK)).toBe(false);
  });

  it("keeps an admin's own readable colour", () => {
    expect(isWashVisibleOn('#1976d2', LIGHT)).toBe(true);
    expect(isWashVisibleOn('#1976d2', DARK)).toBe(true);
  });

  it('changes nothing it cannot read', () => {
    expect(isWashVisibleOn('not-a-hex', LIGHT)).toBe(true);
    expect(isWashVisibleOn(null, LIGHT)).toBe(true);
    expect(isWashVisibleOn('#ffffff', undefined)).toBe(true);
  });
});
