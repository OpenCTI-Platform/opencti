import type { FieldRenderer } from './types';

// Object.create(null) avoids the registry inheriting Object.prototype members
// (e.g. 'constructor', 'toString'), which would otherwise be returned for
// unknown field.type strings and crash React instead of falling back to 'default'.
export const fieldRendererRegistry: Record<string, FieldRenderer> = Object.create(null);

export const registerFieldRenderer = (type: string, renderer: FieldRenderer): void => {
  fieldRendererRegistry[type] = renderer;
};
