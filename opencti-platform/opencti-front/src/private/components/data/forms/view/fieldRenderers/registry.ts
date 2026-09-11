import type { FieldRenderer } from './types';

export const fieldRendererRegistry: Record<string, FieldRenderer> = {};

export const registerFieldRenderer = (type: string, renderer: FieldRenderer): void => {
  fieldRendererRegistry[type] = renderer;
};
