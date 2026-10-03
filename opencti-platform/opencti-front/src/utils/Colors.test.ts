import { describe, it, expect, vi } from 'vitest';
import { hexToRGB, isWashVisibleOn, normalizeLabelColor } from './Colors';

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

describe('Function: normalizeLabelColor', () => {
  // The one form the design system's Chip reads: `#rgb` or `#rrggbb`, nothing else.
  const CHIP_HEX_RE = /^#(?:[0-9a-f]{3}|[0-9a-f]{6})$/i;

  it('keeps a six digit hex, in the case the Chip compares in', () => {
    expect(normalizeLabelColor('#70D907')).toEqual('#70d907');
    expect(normalizeLabelColor('#ffffff')).toEqual('#ffffff');
  });

  it('expands three digit shorthand', () => {
    expect(normalizeLabelColor('#f00')).toEqual('#ff0000');
    expect(normalizeLabelColor('#FFF')).toEqual('#ffffff');
  });

  it('drops the alpha channel the Chip refuses', () => {
    expect(normalizeLabelColor('#f008')).toEqual('#ff0000');
    expect(normalizeLabelColor('#70D90780')).toEqual('#70d907');
  });

  it('resolves CSS colour names, which is the case reported in #17238', () => {
    const colors: Record<string, string> = {
      red: '#ff0000',
      rebeccapurple: '#663399',
      LightBlue: '#add8e6',
    };
    let fillStyle = '#010203';
    const context = {
      get fillStyle() {
        return fillStyle;
      },
      set fillStyle(value: string) {
        fillStyle = colors[value] ?? value;
      },
    } as unknown as CanvasRenderingContext2D;
    const getContext = vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(context);
    try {
      expect(normalizeLabelColor('red')).toEqual('#ff0000');
      expect(normalizeLabelColor('rebeccapurple')).toEqual('#663399');
      expect(normalizeLabelColor('LightBlue')).toEqual('#add8e6');
    } finally {
      getContext.mockRestore();
    }
  });

  it('normalizes a CSS system color through the canvas parser', () => {
    let fillStyle = '#010203';
    const context = {
      get fillStyle() {
        return fillStyle;
      },
      set fillStyle(value: string) {
        fillStyle = value === 'ButtonText' ? 'rgb(0, 0, 0)' : value;
      },
    } as unknown as CanvasRenderingContext2D;
    const getContext = vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(context);
    try {
      expect(normalizeLabelColor('ButtonText')).toBe('#000000');
    } finally {
      getContext.mockRestore();
    }
  });

  it('parses browser hex, rgb, and hsl return values', () => {
    const values: Record<string, string> = {
      'hex-color': '#abc',
      'rgb-color': 'rgb(1, 2, 3)',
      'hsl-color': 'hsl(0, 0%, 0%)',
    };
    let fillStyle = '#010203';
    const context = {
      get fillStyle() {
        return fillStyle;
      },
      set fillStyle(value: string) {
        fillStyle = values[value] ?? value;
      },
    } as unknown as CanvasRenderingContext2D;
    const getContext = vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(context);
    try {
      expect(normalizeLabelColor('hex-color')).toBe('#aabbcc');
      expect(normalizeLabelColor('rgb-color')).toBe('#010203');
      expect(normalizeLabelColor('hsl-color')).toBe('#000000');
    } finally {
      getContext.mockRestore();
    }
  });

  it('returns null when the canvas rejects an assignment', () => {
    let fillStyle = '#010203';
    const context = {
      get fillStyle() {
        return fillStyle;
      },
      set fillStyle(value: string) {
        if (value !== 'not-a-color') {
          fillStyle = value;
        }
      },
    } as unknown as CanvasRenderingContext2D;
    const getContext = vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(context);
    try {
      expect(normalizeLabelColor('not-a-color')).toBeNull();
    } finally {
      getContext.mockRestore();
    }
  });

  it('returns null when the canvas is unavailable', () => {
    const getContext = vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null);
    try {
      expect(normalizeLabelColor('ButtonText')).toBeNull();
    } finally {
      getContext.mockRestore();
    }
  });

  it('rejects malformed numeric color channels', () => {
    const invalid = new Set(['hsl(., 50%, 50%)', 'rgb(., 0, 0)', 'rgb(1.2.3, 0, 0)']);
    let fillStyle = '#010203';
    const context = {
      get fillStyle() {
        return fillStyle;
      },
      set fillStyle(value: string) {
        if (!invalid.has(value)) {
          fillStyle = value;
        }
      },
    } as unknown as CanvasRenderingContext2D;
    const getContext = vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(context);
    try {
      for (const color of invalid) {
        expect(() => {
          expect(normalizeLabelColor(color)).toBeNull();
        }).not.toThrow();
      }
    } finally {
      getContext.mockRestore();
    }
  });

  it('converts functional notations rather than forwarding them', () => {
    let fillStyle = '#010203';
    const context = {
      get fillStyle() {
        return fillStyle;
      },
      set fillStyle(value: string) {
        fillStyle = value;
      },
    } as unknown as CanvasRenderingContext2D;
    const getContext = vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(context);
    try {
      expect(normalizeLabelColor('rgb(112, 217, 7)')).toEqual('#70d907');
      expect(normalizeLabelColor('rgb(112 217 7)')).toEqual('#70d907');
      expect(normalizeLabelColor('rgba(112, 217, 7, 0.5)')).toEqual('#70d907');
      expect(normalizeLabelColor('rgb(50%, 0%, 0%)')).toEqual('#800000');
      expect(normalizeLabelColor('hsl(120, 50%, 50%)')).toEqual('#40bf40');
      expect(normalizeLabelColor('hsla(120, 50%, 50%, 0.5)')).toEqual('#40bf40');
    } finally {
      getContext.mockRestore();
    }
  });

  it('keeps a bare hex, which the Chip already accepts without the hash', () => {
    expect(normalizeLabelColor('70D907')).toEqual('#70d907');
    expect(normalizeLabelColor('f00')).toEqual('#ff0000');
  });

  it('trims surrounding whitespace', () => {
    let fillStyle = '#010203';
    const context = {
      get fillStyle() {
        return fillStyle;
      },
      set fillStyle(value: string) {
        fillStyle = value;
      },
    } as unknown as CanvasRenderingContext2D;
    const getContext = vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(context);
    try {
      expect(normalizeLabelColor('  #70D907  ')).toEqual('#70d907');
      expect(normalizeLabelColor(' rgb(112, 217, 7) ')).toEqual('#70d907');
    } finally {
      getContext.mockRestore();
    }
  });

  it('returns null for anything the Chip could not render either', () => {
    const getContext = vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null);
    try {
      expect(normalizeLabelColor('#12345')).toBeNull();
      expect(normalizeLabelColor('#GGGGGG')).toBeNull();
      expect(normalizeLabelColor('notacolor')).toBeNull();
      expect(normalizeLabelColor('rgb(112, 217)')).toBeNull();
      expect(normalizeLabelColor('')).toBeNull();
      expect(normalizeLabelColor(null)).toBeNull();
      expect(normalizeLabelColor(undefined)).toBeNull();
    } finally {
      getContext.mockRestore();
    }
  });

  it('never returns a value the Chip would reject', () => {
    let fillStyle = '#010203';
    const context = {
      get fillStyle() {
        return fillStyle;
      },
      set fillStyle(value: string) {
        fillStyle = value;
      },
    } as unknown as CanvasRenderingContext2D;
    const getContext = vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(context);
    try {
      const stored = ['#f00', '#f008', '#70D90780', 'rgb(112, 217, 7)', 'hsl(120, 50%, 50%)'];
      for (const color of stored) {
        expect(normalizeLabelColor(color)).toMatch(CHIP_HEX_RE);
      }
    } finally {
      getContext.mockRestore();
    }
  });
});
