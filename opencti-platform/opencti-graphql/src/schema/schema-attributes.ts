import * as R from 'ramda';
import { RULE_PREFIX } from './general';
import { FunctionalError, UnsupportedError } from '../config/errors';
import type { AttributeDefinition, AttrType, ObjectAttribute } from './attribute-definition';
import { shortStringFormats } from './attribute-definition';
import { getParentTypes } from './schemaUtils';

export const depsKeysRegister = {
  deps: [] as { src: string, types?: string[] }[],

  add(deps: { src: string, types?: string[] }[]) {
    this.deps = [...this.get(), ...deps];
  },
  get(): { src: string, types?: string[] }[] {
    return this.deps ?? [];
  },
};

let usageProtection = false;
export const schemaAttributesDefinition = {
  allAttributes: new Map<string, AttributeDefinition>(),
  attributes: {} as Record<string, Map<string, AttributeDefinition>>,
  attributesByTypes: {
    string: new Map<string, void>(),
    date: new Map<string, void>(),
    numeric: new Map<string, void>(),
    boolean: new Map<string, void>(),
    object: new Map<string, void>(),
  } as Record<AttrType, Map<string, void>>,
  registeredTypes: [] as string[],
  upsertByEntity: new Map<string, string[]>(),

  // attributes registration
  registerAttributes(entityType: string, attributes: AttributeDefinition[]) {
    // Check if imported before any business code
    if (usageProtection) {
      throw UnsupportedError('Register attributes use after usage, please check your imports');
    }
    this.registeredTypes.push(entityType);
    const directAttributes = this.attributes[entityType] ?? new Map<string, AttributeDefinition>();
    // Register given attribute
    const currentAttributes = Object.values(this.attributes);
    attributes.forEach((attribute) => {
      // Check different attributes have different labels
      let attributesWithSameLabelAndDifferentName: AttributeDefinition[] = [];
      currentAttributes
        .forEach((m) => {
          const attributeDefinitionsList = Array.from(m.values());
          attributesWithSameLabelAndDifferentName = attributeDefinitionsList.filter((a) => (a.label === attribute.label) && (a.name !== attribute.name));
        });
      if (attributesWithSameLabelAndDifferentName.length > 0) {
        throw UnsupportedError('You can\'t have two attributes with the same label and a different name in the platform', {
          attributesWithSameLabelAndDifferentName,
          attribute,
        });
      }
      // Check the homogeneity of attribute types
      const existingAttribute = currentAttributes.find((a) => a.get(attribute.name))?.get(attribute.name); // Maybe better way ?
      if (existingAttribute) {
        if (existingAttribute.type === 'string') {
          if (existingAttribute.type !== attribute.type) {
            throw UnsupportedError('You can\'t have two attributes with the same name and a different type in the platform', {
              existingAttribute,
              attribute,
            });
          }
          if (existingAttribute.format !== attribute.format) {
            if (!(shortStringFormats.includes(existingAttribute.format) && shortStringFormats.includes(attribute.format))) {
              throw UnsupportedError('You can\'t have two string attributes with the same name and different format if the formats are not both short format', {
                existingAttribute,
                attribute,
              });
            }
          }
        }
        if (existingAttribute.type === 'numeric') {
          if (existingAttribute.type !== attribute.type || existingAttribute.precision !== attribute.precision) {
            throw UnsupportedError('You can\'t have two attributes with the same name and a different type in the platform', {
              existingAttribute,
              attribute,
            });
          }
        }
        if (existingAttribute.type === 'object') {
          if (existingAttribute.type !== attribute.type || existingAttribute.format !== attribute.format) {
            throw UnsupportedError('You can\'t have two attributes with the same name and a different type in the platform', {
              existingAttribute,
              attribute,
            });
          }
        }
        if (existingAttribute.type === 'date' || existingAttribute.type === 'boolean') {
          if (existingAttribute.type !== attribute.type) {
            throw UnsupportedError('You can\'t have two attributes with the same name and a different type in the platform', {
              existingAttribute,
              attribute,
            });
          }
        }
      }
      // Check duplicate attributes
      if (directAttributes.has(attribute.name)) {
        throw UnsupportedError('You can\'t register two attributes with the same name on an entity', {
          attributeName: attribute.name,
          entityType
        });
      }
      // set attribute
      directAttributes.set(attribute.name, attribute);
      // add the attribute name and type in the map of all the attributes
      // to do so, we overwrite an eventual attribute having the same name for an other entity type
      // it's not a problem because if 2 attributes have the same name, they also have the same type
      this.allAttributes.set(attribute.name, attribute);
    });
    const parentAttributes = new Map(getParentTypes(entityType)
      .map((type) => Array.from((this.attributes[type] ?? new Map()).values()))
      .flat()
      .map((e) => [e.name, e]));
    const computedWithParentAttributes = new Map([...parentAttributes, ...directAttributes]);
    this.attributes[entityType] = computedWithParentAttributes;
    computedWithParentAttributes.forEach((attr) => {
      // Generate map by types
      this.attributesByTypes[attr.type as AttrType].set(attr.name);
      // Generate map of upsert by entity type
      if (attr.upsert) {
        this.upsertByEntity.set(entityType, [...this.upsertByEntity.get(entityType) ?? [], attr.name]);
      }
    });
  },

  selectEntityType(entityType: string) {
    usageProtection = true;
    if (this.attributes[entityType]) {
      return entityType;
    }
    const types = [...getParentTypes(entityType)].reverse();
    for (let i = 0; i < types.length; i += 1) {
      const type = types[i];
      if (this.attributes[type]) {
        return type;
      }
    }
    throw UnsupportedError('Register relations has no registration for type', { type: entityType });
  },

  // Usage of raw attributes
  getAllAttributes() {
    usageProtection = true;
    return R.uniqBy((a) => a.name, Object.values(this.attributes).map((a) => Array.from(a.values())).flat());
  },

  getRegisteredTypes() {
    return this.registeredTypes;
  },

  // Usage of getAttributes
  getAttributes(entityType: string): Map<string, AttributeDefinition> {
    // const attributesRefs = schemaRelationsRefDefinition.relationsRefMap(entityType) ?? new Map();
    // const attributes = this.attributesCache.get(entityType) ?? new Map();
    // return new Map([...attributesRefs, ...attributes]);
    return this.attributes[this.selectEntityType(entityType)] ?? new Map();
  },
  getAttributeNames(entityType: string): string[] {
    return Array.from(this.getAttributes(entityType).keys());
  },
  getAttribute(entityType: string, name: string): AttributeDefinition | undefined {
    return this.getAttributes(entityType)?.get(name);
  },
  getAttributeByName(name: string): AttributeDefinition | undefined {
    return this.allAttributes.get(name);
  },
  isMultipleAttribute(entityType: string, attributeName: string): boolean {
    return this.getAttribute(entityType, attributeName)?.multiple ?? false;
  },

  // Usage of allAttributes
  getAllAttributesNames(): Array<string> {
    usageProtection = true;
    return Array.from(this.allAttributes.keys());
  },

  // Usage of upsertByEntity
  getUpsertAttributeNames(entityType: string): string[] {
    return this.upsertByEntity.get(this.selectEntityType(entityType)) ?? [];
  },

  isSpecificTypeAttribute(attributeName: string, ...attributeType: AttrType[]): boolean {
    usageProtection = true;
    return attributeType.reduce((r, fn) => this.attributesByTypes[fn].has(attributeName) || r, false);
  },
};

// -- TYPE --
export const isBooleanAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'boolean')
);
export const isDateAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'date')
);
export const isObjectAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'object')
);
export const isNumericAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'numeric')
);
export const isDateNumericOrBooleanAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'date', 'numeric', 'boolean')
);

export const isObjectFlatAttribute = (k: string): boolean => {
  const definition = schemaAttributesDefinition.getAttributeByName(k.split('.')[0]);
  if (!definition) return false;
  return definition.type === 'object' && definition.format === 'flat';
};

// -- MULTIPLE --

export const isMultipleAttribute = (entityType: string, k: string): boolean => (
  k.startsWith(RULE_PREFIX) || schemaAttributesDefinition.isMultipleAttribute(entityType, k)
);

// region schema validation
const validateObjectAgainstSchema = (value: object, key: string, schemaDef: ObjectAttribute) => {
  if (Array.isArray(value) || !R.is(Object, value)) {
    throw FunctionalError(`Validation against schema failed on attribute [${key}]: value is not an object`, { value });
  }

  // check mandatory fields
  const mandatoryFieldNames = schemaDef.mappings
    .filter((m) => m.mandatoryType === 'external' || m.mandatoryType === 'internal')
    .map(({ name }) => name);
  mandatoryFieldNames.forEach((mandatoryName) => {
    if (!Object.keys(value).includes(mandatoryName)) {
      throw FunctionalError(`Validation against schema failed on attribute [${key}]: mandatory field [${mandatoryName}] is not present`, { value });
    }
  });
};

export const validateElementAgainstSchema = (element: any) => {
  Object.keys(element).forEach((elementKey) => {
    const value = element[elementKey];
    if (isObjectAttribute(elementKey)) {
      const schemaDef = schemaAttributesDefinition.getAttributeByName(elementKey) as ObjectAttribute;
      if (!schemaDef) return;
      if (schemaDef.multiple) {
        if (!Array.isArray(value)) {
          throw FunctionalError(`Validation against schema failed on attribute [${elementKey}]: value is not an array`, { element });
        }
        value.forEach((item) => {
          validateObjectAgainstSchema(item, elementKey, schemaDef);
        });
      } else {
        if (Array.isArray(value) || !R.is(Object, value)) {
          throw FunctionalError(`Validation against schema failed on attribute [${elementKey}]: value is not an object`, { element });
        }
        validateObjectAgainstSchema(value, elementKey, schemaDef);
      }
    }
  });
};
// endregion
