import { describe, expect, it } from 'vitest';
import { createTextGradientSx } from './Button.utils';

const GRADIENT = { start: '#0fbcff', end: '#00f0bc' };

describe('createTextGradientSx', () => {
  it('paints the button own text with the gradient', () => {
    const sx = createTextGradientSx(GRADIENT, 90);
    expect(sx.WebkitTextFillColor).toBe('transparent');
    expect(sx.WebkitBackgroundClip).toBe('text');
  });

  it('does not let the transparent fill reach nested components', () => {
    const sx = createTextGradientSx(GRADIENT, 90);
    // `-webkit-text-fill-color` inherits and beats `color`, so a component nested in a gradient
    // button renders invisible glyphs unless the fill is put back for element children.
    const reset = sx['& > *'];
    expect(reset).toBeDefined();
    expect(reset.WebkitTextFillColor).toBe('currentColor');
    // `background` does not inherit, so resetting it here would only erase a
    // nested component's own fill — which it did, once.
    expect(reset.background).toBeUndefined();
  });

  it('hides the glyphs through the fill alone, so the reset has a colour to resolve to', () => {
    const sx = createTextGradientSx(GRADIENT, 90);
    // The library hides the label with `-webkit-text-fill-color` only.
    expect(sx.color).toBeUndefined();
  });

  it('keeps tinting the leading icon', () => {
    const sx = createTextGradientSx(GRADIENT, 90);
    expect(sx['& svg'].fill).toBe(GRADIENT.start);
  });
});
