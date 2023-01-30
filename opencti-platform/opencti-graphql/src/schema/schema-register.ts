import type { AttributeDefinition } from './module-register';
import type { AttrType } from '../types/module';
import {
  booleanAttributes,
  dateAttributes,
  dictAttributes, jsonAttributes, multipleAttributes,
  numericAttributes,
  runtimeAttributes
} from './fieldDataAdapter';
import { RULE_PREFIX, schemaTypes } from './general';
import { ENTITY_TYPE_DATA_COMPONENT } from './stixDomainObject';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';
import { UnsupportedError } from '../config/errors';

// MISS ad entity type by category (register, add and get method)

export const schemaDefinition = {
  attributes: {} as Record<string, AttributeDefinition[]>,

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

  getAttributes(entityType: string): AttributeDefinition[] { // use in API
    return ((this.attributes)[entityType] ?? []);
  },

  getAttributeNames(entityType: string): string[] { // use in js file
    // NEW mechanism
    if (entityType === ENTITY_TYPE_DATA_COMPONENT || entityType === ENTITY_TYPE_ENTITY_SETTING) {
      return ((this.attributes)[entityType] ?? []).map((attr) => attr.name);
    }
    // OLD mechanism
    return schemaTypes.getAttributes(entityType);
  },

  getAllAttributes(): AttributeDefinition[] {
    return Object.values(this.attributes ?? {}).flat();
  },

  getUpsertAttributeNames(entityType: string): string[] {
    // NEW mechanism
    if (entityType === ENTITY_TYPE_DATA_COMPONENT || entityType === ENTITY_TYPE_ENTITY_SETTING) {
      return ((this.attributes)[entityType] ?? [])
        .filter((attr) => attr.upsert)
        .map((attr) => attr.name);
    }
    // OLD mechanism
    return schemaTypes.getUpsertAttributes(entityType);
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

export const isBooleanAttr = (k: string): boolean => (
  booleanAttributes.includes(k) || schemaDefinition.isSpecificTypeAttribute(k, 'boolean')
);
export const isDateAttr = (k: string): boolean => (
  dateAttributes.includes(k) || schemaDefinition.isSpecificTypeAttribute(k, 'date')
);
export const isDictionaryAttr = (k: string): boolean => (
  dictAttributes.includes(k) || schemaDefinition.isSpecificTypeAttribute(k, 'dictionary')
);
export const isJsonAttr = (k: string): boolean => (
  jsonAttributes.includes(k) || schemaDefinition.isSpecificTypeAttribute(k, 'json')
);
export const isNumericAttr = (k: string): boolean => (
  numericAttributes.includes(k) || schemaDefinition.isSpecificTypeAttribute(k, 'numeric')
);
export const isRuntimeAttr = (k: string): boolean => (
  runtimeAttributes.includes(k) || schemaDefinition.isSpecificTypeAttribute(k, 'runtime') // Add it to the global attr type declaration ???
);

export const isDateNumericOrBooleanAttr = (k: string): boolean => (
  dateAttributes.includes(k)
  || [...numericAttributes, ...booleanAttributes].includes(k)
  || schemaDefinition.isSpecificTypeAttribute(k, 'date', 'numeric', 'boolean')
);

// -- MULTIPLE --

export const isMultipleAttr = (k: string): boolean => (
  k.startsWith(RULE_PREFIX) || multipleAttributes.includes(k) || schemaDefinition.isMultipleAttribute(k)
);
