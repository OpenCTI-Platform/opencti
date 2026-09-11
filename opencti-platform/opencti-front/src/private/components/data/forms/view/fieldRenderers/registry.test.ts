import { describe, it, expect, afterEach } from 'vitest';
import { fieldRendererRegistry, registerFieldRenderer } from './registry';

describe('fieldRendererRegistry', () => {
  const originalKeys = Object.keys(fieldRendererRegistry);

  afterEach(() => {
    Object.keys(fieldRendererRegistry).forEach((key) => {
      if (!originalKeys.includes(key)) {
        delete fieldRendererRegistry[key];
      }
    });
  });

  it('starts empty until adapters register themselves', () => {
    expect(fieldRendererRegistry).toEqual({});
  });

  it('allows registering a renderer for a field type', () => {
    const renderer = () => null;
    registerFieldRenderer('custom-type', renderer);
    expect(fieldRendererRegistry['custom-type']).toBe(renderer);
  });

  it('allows overwriting a previously registered renderer', () => {
    const rendererA = () => null;
    const rendererB = () => null;
    registerFieldRenderer('custom-type', rendererA);
    registerFieldRenderer('custom-type', rendererB);
    expect(fieldRendererRegistry['custom-type']).toBe(rendererB);
  });
});
