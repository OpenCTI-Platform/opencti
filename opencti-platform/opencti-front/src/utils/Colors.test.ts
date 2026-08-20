import { describe, it, expect } from 'vitest';
import { hexToRGB, isHexColor } from './Colors';

describe('Function: hexToRGB', () => {
  it('should return matching rgb color', () => {
    expect(hexToRGB('#70D907', 1)).toEqual('rgb(112, 217, 7, 1)');
  });

  it('should return default alpha value', () => {
    expect(hexToRGB('#70D907')).toEqual('rgb(112, 217, 7, 0.1)');
  });
});

describe('Function: isHexColor', () => {
  it('should accept six digit hex colors', () => {
    expect(isHexColor('#70D907')).toBe(true);
    expect(isHexColor('#ffffff')).toBe(true);
    expect(isHexColor('#ABCDEF')).toBe(true);
  });

  it('should accept three digit shorthand hex colors', () => {
    expect(isHexColor('#f00')).toBe(true);
    expect(isHexColor('#FFF')).toBe(true);
  });

  it('should reject CSS color names, which MUI alpha() cannot parse', () => {
    expect(isHexColor('red')).toBe(false);
    expect(isHexColor('rebeccapurple')).toBe(false);
  });

  it('should reject malformed hex values', () => {
    expect(isHexColor('#12345')).toBe(false);
    expect(isHexColor('#GGGGGG')).toBe(false);
    expect(isHexColor('70D907')).toBe(false);
    expect(isHexColor('#70D907 ')).toBe(false);
  });

  it('should reject empty values', () => {
    expect(isHexColor('')).toBe(false);
    expect(isHexColor(null)).toBe(false);
    expect(isHexColor(undefined)).toBe(false);
  });
});
