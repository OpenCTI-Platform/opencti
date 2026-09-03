import { alpha } from '@mui/material';
import { describe, it, expect } from 'vitest';
import { CSS_NAMED_COLORS, hexToRGB, normalizeLabelColor } from './Colors';

describe('Function: hexToRGB', () => {
  it('should return matching rgb color', () => {
    expect(hexToRGB('#70D907', 1)).toEqual('rgb(112, 217, 7, 1)');
  });

  it('should return default alpha value', () => {
    expect(hexToRGB('#70D907')).toEqual('rgb(112, 217, 7, 0.1)');
  });
});

describe('Function: normalizeLabelColor', () => {
  it('should keep six digit hex colors untouched', () => {
    expect(normalizeLabelColor('#70D907')).toEqual('#70D907');
    expect(normalizeLabelColor('#ffffff')).toEqual('#ffffff');
  });

  it('should expand three digit shorthand hex colors', () => {
    expect(normalizeLabelColor('#f00')).toEqual('#FF0000');
    expect(normalizeLabelColor('#FFF')).toEqual('#FFFFFF');
  });

  it('should expand four digit shorthand hex colors with alpha', () => {
    expect(normalizeLabelColor('#f008')).toEqual('#FF000088');
  });

  it('should keep eight digit hex colors untouched', () => {
    expect(normalizeLabelColor('#70D90780')).toEqual('#70D90780');
  });

  it('should resolve CSS colour names to hex', () => {
    expect(normalizeLabelColor('red')).toEqual('#ff0000');
    expect(normalizeLabelColor('rebeccapurple')).toEqual('#663399');
    expect(normalizeLabelColor('LightBlue')).toEqual('#add8e6');
  });

  it('should pass functional rgb/hsl notations through', () => {
    expect(normalizeLabelColor('rgb(112, 217, 7)')).toEqual('rgb(112, 217, 7)');
    expect(normalizeLabelColor('hsl(120, 50%, 50%)')).toEqual('hsl(120, 50%, 50%)');
    expect(normalizeLabelColor('rgba(112, 217, 7, 0.5)')).toEqual('rgba(112, 217, 7, 0.5)');
  });

  it('should trim surrounding whitespace', () => {
    expect(normalizeLabelColor('  #70D907  ')).toEqual('#70D907');
    expect(normalizeLabelColor(' red ')).toEqual('#ff0000');
  });

  it('should reject malformed or unknown values', () => {
    expect(normalizeLabelColor('#12345')).toBeNull();
    expect(normalizeLabelColor('#GGGGGG')).toBeNull();
    expect(normalizeLabelColor('70D907')).toBeNull();
    expect(normalizeLabelColor('notacolor')).toBeNull();
    expect(normalizeLabelColor('rgb(112, 217)')).toBeNull();
  });

  it('should reject empty values', () => {
    expect(normalizeLabelColor('')).toBeNull();
    expect(normalizeLabelColor('   ')).toBeNull();
    expect(normalizeLabelColor(null)).toBeNull();
    expect(normalizeLabelColor(undefined)).toBeNull();
  });

  it('should cover the full CSS named colour list', () => {
    expect(Object.keys(CSS_NAMED_COLORS)).toHaveLength(148);
  });

  it('should produce values MUI alpha() can parse, the actual bug of #17238', () => {
    expect(alpha(normalizeLabelColor('red') as string, 0.2)).toEqual('rgba(255, 0, 0, 0.2)');
    expect(alpha(normalizeLabelColor('#f00') as string, 0.2)).toEqual('rgba(255, 0, 0, 0.2)');
    expect(() => alpha('red', 0.2)).toThrow();
  });
});
