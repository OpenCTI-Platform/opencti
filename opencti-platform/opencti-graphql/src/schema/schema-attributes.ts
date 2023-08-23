import * as R from 'ramda';
import { ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT, RULE_PREFIX } from './general';
import { UnsupportedError } from '../config/errors';
import type { AttributeDefinition, AttrType } from './attribute-definition';
import { getParentTypes } from './schemaUtils';
import { schemaTypesDefinition } from './schema-types';
import { ATTRIBUTE_NAME } from './stixDomainObject';

const EXCLUDED_SEARCH_ATTRIBUTES = [
  'id',
  'internal_id',
  'creator_id',
  'user_id',
  'x_opencti_workflow_id',
  'i_aliases_ids',
  'parent_types',
  'base_type',
  'entity_type',
  'x_opencti_graph_data',
  'default_dashboard',
  'default_hidden_types',
  'payload_bin',
  'extensions',
];

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
  attributes: {} as Record<string, Map<string, AttributeDefinition>>,
  // allAttributes is a map of the name and type of all the attributes registered in a schema definition
  // !!! don't use this map !!! It is created for the special context of filter keys checking in case no entity types are given
  allAttributes: new Map<string, string>(),
  attributesCache: new Map<string, Map<string, AttributeDefinition>>(),

  attributesByTypes: {
    string: new Map<string, void>(),
    date: new Map<string, void>(),
    numeric: new Map<string, void>(),
    boolean: new Map<string, void>(),
    dictionary: new Map<string, void>(),
    object: new Map<string, void>(),
    json: new Map<string, void>(),
    object: new Map<string, void>(),
    runtime: new Map<string, void>(),
  } as Record<AttrType, Map<string, void>>,
  upsertByEntity: new Map<string, string[]>(),

  // attributes
  registerAttributes(entityType: string, attributes: AttributeDefinition[]) {
    const directAttributes = this.attributes[entityType] ?? new Map<string, AttributeDefinition>();

    // Register given attribute
    const allAttributes = Object.values(this.attributes);
    attributes.forEach((attribute) => {
      // Check the homogeneity of attribute types
      const existingAttribute = allAttributes.find((a) => a.get(attribute.name))?.get(attribute.name); // Maybe better way ?
      if (existingAttribute && existingAttribute.type !== attribute.type) {
        throw UnsupportedError('You can\'t have two attributes with the same name and a different type in the platform', {
          existingAttribute,
          attribute,
        });
      }
      // Check duplicate attributes
      if (directAttributes.has(attribute.name)) {
        throw UnsupportedError('You can\'t register two attributes with the same name on an entity', {
          attributeName: attribute.name,
          entityType
        });
      }
      // Check if attribute is not already part of a parent
      const parentTypes = getParentTypes(entityType);
      for (let i = 0; i < parentTypes.length; i += 1) {
        const parentType = parentTypes[i];
        const attrList = Array.from((this.attributes[parentType] ?? new Map()).values()).flat();
        const attrMap = new Map(attrList.map((e) => [e.name, e]));
        const parentAttribute = attrMap.get(attribute.name);
        // We throw if we found the exact same definition (to allow attribute override)
        const uniqAttribute = R.omit(['mandatoryType'], attribute);
        const uniqParentAttribute = R.omit(['mandatoryType'], parentAttribute);
        if (parentAttribute && R.equals(uniqAttribute, uniqParentAttribute)) {
          throw UnsupportedError('Attribute already defined by one of its parent', {
            entityType,
            parentType,
            attribute,
            parentAttribute,
          });
        }
      }
      // Set the attribute in list
      directAttributes.set(attribute.name, attribute);
      // add the attribute name and type in the map of all the attributes
      // to do so, we overwrite an eventual attribute having the same name for an other entity type
      // it's not a problem because if 2 attributes have the same name, they also have the same type
      this.allAttributes.set(attribute.name, attribute.type);
    });
    this.attributes[entityType] = directAttributes;
    this.computeCache(entityType);
  },

  // Extract this method to be call in all methods
  // When an entity not register any relations, the relations for this entity is not computed
  // Call only in register mechanism when all the entities will be migrated
  computeCache(entityType: string) {
    if (this.attributesCache.has(entityType)) return;

    const directAttributes = this.attributes[entityType] ?? [];
    // Register inheritance attributes
    const parentAttributes = new Map(
      getParentTypes(entityType)
        .map((type) => Array.from((this.attributes[type] ?? new Map()).values()))
        .flat()
        .map((e) => [e.name, e])
    );
    const computedWithParentAttributes = new Map([...parentAttributes, ...directAttributes]);
    this.attributesCache.set(entityType, computedWithParentAttributes);

    // Generate cache map
    computedWithParentAttributes.forEach((attr) => {
      // Generate map by types
      this.attributesByTypes[attr.type as AttrType].set(attr.name);
      // Generate map of upsert by entity type
      if (attr.upsert) {
        this.upsertByEntity.set(entityType, [...this.upsertByEntity.get(entityType) ?? [], attr.name]);
      }
    });
  },

  getAllAttributes() {
    return R.uniqBy((a) => a.name, Object.values(this.attributes).map((a) => Array.from(a.values())).flat());
  },

  getSearchAttributes() {
    const entityTypes = [...schemaTypesDefinition.get(ABSTRACT_STIX_DOMAIN_OBJECT), ...schemaTypesDefinition.get(ABSTRACT_STIX_CYBER_OBSERVABLE)];
    const attributes = entityTypes.map((e) => Array.from(this.getAttributes(e).values())).flat();
    const grouped = R.groupBy((a) => a.name, attributes.filter((a) => a.type === 'string' && !EXCLUDED_SEARCH_ATTRIBUTES.includes(a.name)));
    return Object.entries(grouped).map(([name, definitions]) => {
      if (name === ATTRIBUTE_NAME) {
        return `${name}^100`; // Ensure mame will be first.
      }
      return `${name}^${definitions?.length ?? 0}`;
    });
  },

  getAttributes(entityType: string): Map<string, AttributeDefinition> {
    this.computeCache(entityType);
    return this.attributesCache.get(entityType) ?? new Map();
  },

  getAllAttributesNames(): Array<string> {
    return Array.from(this.allAttributes.keys());
  },

  getAttributeNames(entityType: string): string[] {
    this.computeCache(entityType);
    return Array.from(this.getAttributes(entityType).keys());
  },

  getAttribute(entityType: string, name: string): AttributeDefinition | null {
    this.computeCache(entityType);
    return this.getAttributes(entityType)?.get(name) ?? null;
  },

  getUpsertAttributeNames(entityType: string): string[] {
    this.computeCache(entityType);
    return this.upsertByEntity.get(entityType) ?? [];
  },

  isMultipleAttribute(entityType: string, attributeName: string): boolean {
    this.computeCache(entityType);
    return this.getAttribute(entityType, attributeName)?.multiple ?? false;
  },

  isSpecificTypeAttribute(attributeName: string, ...attributeType: AttrType[]): boolean {
    return attributeType.reduce((r, fn) => this.attributesByTypes[fn].has(attributeName) || r, false);
  },

};

// -- TYPE --
export const isStringAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'string')
);
export const isBooleanAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'boolean')
);
export const isDateAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'date')
);
export const isStringAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'string')
);
export const isDictionaryAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'dictionary')
);
export const isObjectAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'object')
);
export const isJsonAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'json')
);
export const isNumericAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'numeric')
);
export const isDateNumericOrBooleanAttribute = (k: string): boolean => (
  schemaAttributesDefinition.isSpecificTypeAttribute(k, 'date', 'numeric', 'boolean')
);

// -- MULTIPLE --

export const isMultipleAttribute = (entityType: string, k: string): boolean => (
  k.startsWith(RULE_PREFIX) || schemaAttributesDefinition.isMultipleAttribute(entityType, k)
);
