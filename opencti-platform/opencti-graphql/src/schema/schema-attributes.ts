import { RULE_PREFIX } from './general';
import { UnsupportedError } from '../config/errors';
import type { AttributeDefinition, AttrType } from './attribute-definition';

export const depsKeysRegister = {
  deps: [] as { src: string, types?: string[] }[],

  add(deps: { src: string, types?: string[] }[]) {
    this.deps = [...this.get(), ...deps];
  },
  get(): { src: string, types?: string[] }[] {
    return this.deps ?? [];
  },
};

export const schemaAttributesDefinition = {
  types: {} as Record<string, string[]>,
  attributes: {} as Record<string, AttributeDefinition[]>,

  // types
  register(type: string, children: string[]) {
    this.types[type] = children;
  },
  add(type: string, children: string[] | string) {
    const values = Array.isArray(children) ? children : [children];
    this.types[type] = [...this.get(type), ...values];
  },
  get(type: string): string[] {
    return this.types[type] ?? [];
  },

  // attributes
  registerAttributes(entityType: string, attributes: AttributeDefinition[]) {
    // Check the homogeneity of attribute types
    const allAttributes = this.getAllAttributes();
    attributes.forEach((attribute) => {
      const existingAttribute = allAttributes.find((a) => a.name === attribute.name);
      if (existingAttribute && existingAttribute.type !== attribute.type) {
        throw UnsupportedError('You can\'t have two attribute with the same name and a different type in the platform', {
          existingAttribute,
          attribute,
        });
      }
    });

    this.attributes[entityType] = attributes;
  },

  getAttributes(entityType: string): AttributeDefinition[] {
    return ((this.attributes)[entityType] ?? []);
  },

  getAttributeNames(entityType: string): string[] {
    return ((this.attributes)[entityType] ?? []).map((attr) => attr.name);
  },

  getAllAttributes(): AttributeDefinition[] {
    return Object.values(this.attributes ?? {}).flat();
  },

  getUpsertAttributeNames(entityType: string): string[] {
    return ((this.attributes)[entityType] ?? [])
      .filter((attr) => attr.upsert)
      .map((attr) => attr.name);
  },

  isMultipleAttribute(attributeName: string): boolean {
    return this.getAllAttributes()
      .filter((attr) => attr.multiple)
      .map((attr) => attr.name)
      .includes(attributeName);
  },

  isSpecificTypeAttribute(attributeName: string, ...attributeType: AttrType[]): boolean {
    return this.getAllAttributes()
      .filter((attr) => attributeType.includes(attr.type))
      .map((attr) => attr.name)
      .includes(attributeName);
  },

};

// -- TYPE --

// TODO Transform to map
export const isBooleanAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'boolean')
);
export const isDateAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'date')
);
export const isDictionaryAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'dictionary')
);
export const isJsonAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'json')
);
export const isNumericAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'numeric')
);
export const isRuntimeAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'runtime')
);

export const isDateNumericOrBooleanAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'date', 'numeric', 'boolean')
);

// -- MULTIPLE --

// TODO Transform to map
export const isMultipleAttribute = (k: string): boolean => (
  k.startsWith(RULE_PREFIX) || schemaAttributesDefinition.isMultipleAttribute(k)
);
