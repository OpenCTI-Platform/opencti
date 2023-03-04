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
  types: {} as Record<string, Map<string, void>>,
  attributes: {} as Record<string, AttributeDefinition[]>,
  attributes_by_types: {
    string: new Map<string, void>(),
    date: new Map<string, void>(),
    numeric: new Map<string, void>(),
    boolean: new Map<string, void>(),
    dictionary: new Map<string, void>(),
    json: new Map<string, void>(),
    runtime: new Map<string, void>(),
  } as Record<AttrType, Map<string, void>>,
  attributes_multiple: new Map<string, void>(),
  upsert_by_entity: new Map<string, string[]>(),

  // types
  isTypeIncludedIn(type: string, parent: string) {
    return this.types[parent].has(type);
  },
  register(type: string, children: string[]) {
    this.types[type] = new Map(children.map((c) => [c, undefined]));
  },
  add(type: string, children: string[] | string) {
    const values = Array.isArray(children) ? children : [children];
    const currentMap = this.types[type];
    if (currentMap) {
      values.forEach((v) => currentMap.set(v));
    } else {
      this.types[type] = new Map(values.map((c) => [c, undefined]));
    }
  },
  get(type: string): string[] {
    return Array.from(this.types[type].keys());
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
      // Generate map by types
      this.attributes_by_types[attribute.type].set(attribute.name);
      // Generate map by multiple
      if (attribute.multiple) {
        this.attributes_multiple.set(attribute.name);
      }
      // Generate map of upsert by entity type
      if (attribute.upsert) {
        const currentList = this.upsert_by_entity.get(entityType);
        if (currentList) {
          currentList.push(attribute.name);
        } else {
          this.upsert_by_entity.set(entityType, [attribute.name]);
        }
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
    return this.upsert_by_entity.get(entityType) ?? [];
  },

  isMultipleAttribute(attributeName: string): boolean {
    return this.attributes_multiple.has(attributeName);
  },

  isSpecificTypeAttribute(attributeName: string, ...attributeType: AttrType[]): boolean {
    return attributeType.reduce((r, fn) => this.attributes_by_types[fn].has(attributeName) || r, false);
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
