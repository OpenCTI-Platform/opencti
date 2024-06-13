import { uniq } from 'ramda';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { schemaTypesDefinition } from '../schema/schema-types';
import type {
  AttributeDefinition,
  ComplexAttributeWithMappings,
  EnumAttribute,
  IdAttribute,
  NumericAttribute,
  RefAttribute,
  StringAttribute,
  VocabAttribute,
} from '../schema/attribute-definition';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { isStixCoreObject } from '../schema/stixCoreObject';
import {
  ALIAS_FILTER,
  COMPUTED_RELIABILITY_FILTER,
  CONNECTED_TO_INSTANCE_FILTER,
  CONTEXT_CREATED_BY_FILTER,
  CONTEXT_CREATOR_FILTER,
  CONTEXT_ENTITY_ID_FILTER,
  CONTEXT_ENTITY_TYPE_FILTER,
  CONTEXT_OBJECT_LABEL_FILTER,
  CONTEXT_OBJECT_MARKING_FILTER,
  INSTANCE_REGARDING_OF,
  MEMBERS_GROUP_FILTER,
  MEMBERS_ORGANIZATION_FILTER,
  MEMBERS_USER_FILTER,
  OBJECT_CONTAINS_FILTER,
  REPRESENTATIVE_FILTER,
  TYPE_FILTER,
  WORKFLOW_FILTER,
} from '../utils/filtering/filtering-constants';
import { ABSTRACT_STIX_CORE_OBJECT, INPUT_GRANTED_REFS, isAbstract } from '../schema/general';
import { getEntityFromCache } from '../database/cache';
import type { BasicStoreSettings } from '../types/settings';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_HISTORY, ENTITY_TYPE_SETTINGS, ENTITY_TYPE_STATUS_TEMPLATE, ENTITY_TYPE_USER } from '../schema/internalObject';
import { isEmptyField } from '../database/utils';
import { ENTITY_HASHED_OBSERVABLE_ARTIFACT } from '../schema/stixCyberObservable';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL, ENTITY_TYPE_IDENTITY_SECTOR, ENTITY_TYPE_IDENTITY_SYSTEM, isStixObjectAliased } from '../schema/stixDomainObject';
import { ENTITY_TYPE_MALWARE_ANALYSIS } from '../modules/malwareAnalysis/malwareAnalysis-types';
import { isBasicRelationship, isStixRelationship, isStixRelationshipExceptRef } from '../schema/stixRelationship';
import { ENTITY_TYPE_LABEL, ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';

export type FilterDefinition = {
  filterKey: string
  type: string // possible values: boolean, date, integer, float, string, id, vocabulary, text, enum, object, nested
  label: string // filter key translation in English
  multiple: boolean, // if the field can have multiple values
  subEntityTypes: string[] // entity types that have the given type as parent and have this filter key in their schema
  elementsForFilterValuesSearch: string[] // not empty if type = id, type = enum or type = vocabulary
  subFilters?: FilterDefinition[]
};

// build the FilterDefinition object that is saved in the filterKeysShema
// by removing some useless attributes of AttributeDefinition
// and adding the subEntityTypes (usage in the subtypes)
const buildFilterDefinitionFromAttributeDefinition = (attributeDefinition: AttributeDefinition, subEntityTypes: string[]) => {
  let type = attributeDefinition.type as string;
  let elementsForFilterValuesSearch = [] as string[];
  // construct the filter type (and eventually fill elementsForFilterValuesSearch)
  // depending on the attribute type and format
  if (attributeDefinition.type === 'numeric') {
    if ((attributeDefinition as NumericAttribute).precision === 'float') {
      type = 'float';
    } else {
      type = 'integer';
    }
  } else if (attributeDefinition.type === 'string') {
    if ((attributeDefinition as StringAttribute).format === 'id') {
      type = 'id';
      elementsForFilterValuesSearch = (attributeDefinition as IdAttribute).entityTypes;
    } else if ((attributeDefinition as StringAttribute).format === 'short') {
      type = 'string';
    } else if ((attributeDefinition as StringAttribute).format === 'vocabulary') {
      type = 'vocabulary';
      elementsForFilterValuesSearch = [(attributeDefinition as VocabAttribute).vocabularyCategory];
    } else if (['text', 'json'].includes((attributeDefinition as StringAttribute).format)) {
      type = 'text';
    } else if ((attributeDefinition as StringAttribute).format === 'enum') {
      type = 'enum';
      elementsForFilterValuesSearch = (attributeDefinition as EnumAttribute).values;
    } else {
      throw Error(`A string attribute definition format can be 'id', 'short', 'text' or 'json', but not ${attributeDefinition.format}`);
    }
  }
  // return the filter definition
  return {
    filterKey: attributeDefinition.name,
    type,
    label: attributeDefinition.label,
    multiple: attributeDefinition.multiple,
    subEntityTypes,
    elementsForFilterValuesSearch,
  };
};

// build the FilterDefinition object that is saved in the filterKeysShema
// by removing some useless attributes of RelationRefDefinition
// and adding the subEntityTypes (usage in the subtypes)
const buildFilterDefinitionFromRelationRefDefinition = (refDefinition: RefAttribute, subEntityTypes: string[]) => {
  return {
    filterKey: refDefinition.name,
    type: 'id',
    label: refDefinition.label,
    multiple: refDefinition.multiple,
    subEntityTypes,
    elementsForFilterValuesSearch: refDefinition.toTypes,
  };
};

// complete a filter definition (attribute or relation ref) in an under-construction map of filter definitions
// - if the filter key is not present: add the filter definition in the map
// - if it is already present: add the entity types in 'subEntityTypes' of the associated filter definition of the map
const completeFilterDefinitionMapWithElement = (
  filterKeyDefinitionMap: Map<string, FilterDefinition>,
  types: string[],
  elementName: string,
  elementDefinition: AttributeDefinition | RefAttribute,
  elementDefinitionType: string, // 'attribute' or 'relationRef'
) => {
  const filterDefinition = filterKeyDefinitionMap.get(elementName);
  if (!filterDefinition) { // case 1.2.2: the attribute is in the types but not in the map
    const newFilterDefinition = elementDefinitionType === 'attribute'
      ? buildFilterDefinitionFromAttributeDefinition(elementDefinition as AttributeDefinition, types)
      : buildFilterDefinitionFromRelationRefDefinition(elementDefinition as RefAttribute, types);
    filterKeyDefinitionMap.set( // add it in the map
      elementName,
      newFilterDefinition,
    );
  } else if (filterDefinition && !types.every((type) => filterDefinition.subEntityTypes.includes(type))) {
    // 1.2.1 the filter definition is in the map but all the types are not in subEntityTypes
    filterKeyDefinitionMap.set(
      elementName,
      { ...filterDefinition, subEntityTypes: uniq(filterDefinition.subEntityTypes.concat(types)) }, // add types in subEntityTypes of the filter definition
    );
  }
};

const completeFilterDefinitionMapWithObjectAttributeWithMappings = (
  attributesMapWithFilterDefinition: Map<string, FilterDefinition>, // map in construction
  objectAttributeDefinition: ComplexAttributeWithMappings, // object attribute with mappings
  types: string[], // entity types to apply
) => {
  const { mappings } = objectAttributeDefinition;
  mappings.forEach((mappingAttributeDefinition) => {
    if (mappingAttributeDefinition.isFilterable) {
      if (mappingAttributeDefinition.type === 'object' && ['nested', 'standard'].includes(mappingAttributeDefinition.format)) { // case 1: object attribute with mappings
        const composedMappingName = `${objectAttributeDefinition.name}.${mappingAttributeDefinition.name}`;
        completeFilterDefinitionMapWithObjectAttributeWithMappings(
          attributesMapWithFilterDefinition,
          { ...mappingAttributeDefinition, name: composedMappingName } as ComplexAttributeWithMappings,
          types
        );
      } else if (mappingAttributeDefinition.associatedFilterKeys) { // case 2: attribute with no mappings and associatedFilterKeys is set
        // the keys to add are the ones in associatedFilterKeys
        mappingAttributeDefinition.associatedFilterKeys.forEach(({ key, label }) => {
          completeFilterDefinitionMapWithElement(attributesMapWithFilterDefinition, types, key, { ...mappingAttributeDefinition, name: key, label }, 'attribute');
        });
      } else { // case 3: attribute with no mappings and the key to add is composed with the attribute name and the mapping attribute name
        const composedMappingName = `${objectAttributeDefinition.name}.${mappingAttributeDefinition.name}`;
        completeFilterDefinitionMapWithElement(attributesMapWithFilterDefinition, types, composedMappingName, { ...mappingAttributeDefinition, name: composedMappingName }, 'attribute');
      }
    }
  });
};

const completeFilterDefinitionMapForType = (
  filterDefinitionMap: Map<string, FilterDefinition>, // filter definition map to complete
  type: string, // type whose attributes and relations refs to study (eventually add them in the map or complete subEntityTypes)
  subTypes?: string[]
) => {
  // 01. add the attributes
  const attributesMap = schemaAttributesDefinition.getAttributes(type);
  const types = subTypes ? subTypes.concat(type) : [type];
  attributesMap.forEach((attributeDefinition, attributeName) => {
    if (attributeDefinition.isFilterable) { // if it is filterable
      if (attributeDefinition.type === 'object' && ['nested', 'standard'].includes(attributeDefinition.format)) { // case 1.1: attribute with mappings
        completeFilterDefinitionMapWithObjectAttributeWithMappings(filterDefinitionMap, attributeDefinition as ComplexAttributeWithMappings, types);
      } else { // case 1.2: attribute with no mappings
        completeFilterDefinitionMapWithElement(filterDefinitionMap, types, attributeName, attributeDefinition, 'attribute');
      }
    }
  });
  // 02. add the relation refs
  if (schemaRelationsRefDefinition.getRegisteredTypes().includes(type)) {
    const relationRefs = schemaRelationsRefDefinition.getRelationsRef(type);
    relationRefs.forEach((ref) => {
      if (ref.isFilterable) {
        completeFilterDefinitionMapWithElement(filterDefinitionMap, types, ref.name, ref, 'relationRef');
      }
    });
  }
};

const completeFilterDefinitionMapWithSpecialKeys = (
  type: string,
  filterDefinitionsMap: Map<string, FilterDefinition>, // filter definition map to complete
  subEntityTypes: string[],
) => {
  if (isStixCoreObject(type)) {
    // In regards of (exist relationship of the given relationship types for the given entities)
    filterDefinitionsMap.set(INSTANCE_REGARDING_OF, {
      filterKey: INSTANCE_REGARDING_OF,
      type: 'nested',
      label: 'In regards of',
      multiple: true,
      subEntityTypes,
      elementsForFilterValuesSearch: [],
      subFilters: [
        {
          filterKey: 'relationship_type',
          type: 'string',
          label: 'Relationship type',
          multiple: true,
          elementsForFilterValuesSearch: [],
          subEntityTypes: [],
        },
        {
          filterKey: 'id',
          type: 'id',
          label: 'Entity',
          multiple: true,
          elementsForFilterValuesSearch: ['Stix-Core-Object'],
          subEntityTypes: [],
        }
      ]
    });
    // Computed reliability (reliability of the entity, or of its author if no reliability is set)
    filterDefinitionsMap.set(COMPUTED_RELIABILITY_FILTER, {
      filterKey: COMPUTED_RELIABILITY_FILTER,
      type: 'vocabulary',
      label: 'Reliability (self or author)',
      multiple: false,
      subEntityTypes,
      elementsForFilterValuesSearch: ['reliability_ov'],
    });
    // 'contains' is not only for containers, but might be used in any sro or sco as in "contained inside"
    if (isStixCoreObject(type) || isStixRelationship(type)) {
      filterDefinitionsMap.set(OBJECT_CONTAINS_FILTER, {
        filterKey: OBJECT_CONTAINS_FILTER,
        type: 'id',
        label: 'Contains',
        multiple: true,
        subEntityTypes,
        elementsForFilterValuesSearch: [],
      });
    }
    // Alias (handle both 'aliases' and 'x_opencti_aliases' attributes
    if (isStixObjectAliased(type)) {
      filterDefinitionsMap.set(ALIAS_FILTER, {
        filterKey: ALIAS_FILTER,
        type: 'string',
        label: 'Aliases',
        multiple: true,
        subEntityTypes,
        elementsForFilterValuesSearch: [],
      });
    }
    // Workflow status (handle both status and status template of the status)
    if (![ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_TYPE_MALWARE_ANALYSIS].includes(type)) {
      filterDefinitionsMap.set(WORKFLOW_FILTER, {
        filterKey: WORKFLOW_FILTER,
        type: 'id',
        label: 'Status',
        multiple: false,
        subEntityTypes,
        elementsForFilterValuesSearch: [ENTITY_TYPE_STATUS_TEMPLATE],
      });
    }
  }
  if (type === ENTITY_TYPE_HISTORY) {
    // add context filters
    filterDefinitionsMap.set(CONTEXT_OBJECT_LABEL_FILTER, {
      filterKey: CONTEXT_OBJECT_LABEL_FILTER,
      type: 'id',
      label: 'Label of related entity',
      multiple: true,
      subEntityTypes,
      elementsForFilterValuesSearch: [ENTITY_TYPE_LABEL],
    });
    filterDefinitionsMap.set(CONTEXT_OBJECT_MARKING_FILTER, {
      filterKey: CONTEXT_OBJECT_MARKING_FILTER,
      type: 'id',
      label: 'Marking of related entity',
      multiple: true,
      subEntityTypes,
      elementsForFilterValuesSearch: [ENTITY_TYPE_MARKING_DEFINITION],
    });
    filterDefinitionsMap.set(CONTEXT_CREATOR_FILTER, {
      filterKey: CONTEXT_CREATOR_FILTER,
      type: 'id',
      label: 'Creator of related entity',
      multiple: true,
      subEntityTypes,
      elementsForFilterValuesSearch: [ENTITY_TYPE_USER],
    });
    filterDefinitionsMap.set(CONTEXT_CREATED_BY_FILTER, {
      filterKey: CONTEXT_CREATED_BY_FILTER,
      type: 'id',
      label: 'Author of related entity',
      multiple: false,
      subEntityTypes,
      elementsForFilterValuesSearch: [ENTITY_TYPE_IDENTITY_INDIVIDUAL, ENTITY_TYPE_IDENTITY_SECTOR, ENTITY_TYPE_IDENTITY_SYSTEM, ENTITY_TYPE_IDENTITY_ORGANIZATION],
    });
    filterDefinitionsMap.set(CONTEXT_ENTITY_TYPE_FILTER, {
      filterKey: CONTEXT_ENTITY_TYPE_FILTER,
      type: 'string',
      label: 'Type of related entity',
      multiple: true,
      subEntityTypes,
      elementsForFilterValuesSearch: [],
    });
    filterDefinitionsMap.set(CONTEXT_ENTITY_ID_FILTER, {
      filterKey: CONTEXT_ENTITY_ID_FILTER,
      type: 'id',
      label: 'Related entity',
      multiple: true,
      subEntityTypes,
      elementsForFilterValuesSearch: [ABSTRACT_STIX_CORE_OBJECT, ENTITY_TYPE_USER, ENTITY_TYPE_GROUP],
    });
    // add members filters
    filterDefinitionsMap.set(MEMBERS_USER_FILTER, {
      filterKey: MEMBERS_USER_FILTER,
      type: 'id',
      label: 'User',
      multiple: true,
      subEntityTypes,
      elementsForFilterValuesSearch: [ENTITY_TYPE_USER],
    });
    filterDefinitionsMap.set(MEMBERS_GROUP_FILTER, {
      filterKey: MEMBERS_GROUP_FILTER,
      type: 'id',
      label: 'Group',
      multiple: true,
      subEntityTypes,
      elementsForFilterValuesSearch: [ENTITY_TYPE_GROUP],
    });
    filterDefinitionsMap.set(MEMBERS_ORGANIZATION_FILTER, {
      filterKey: MEMBERS_ORGANIZATION_FILTER,
      type: 'id',
      label: 'Organization',
      multiple: true,
      subEntityTypes,
      elementsForFilterValuesSearch: [ENTITY_TYPE_IDENTITY_ORGANIZATION],
    });
  }
  if (isStixRelationshipExceptRef(type)) {
    filterDefinitionsMap.set(WORKFLOW_FILTER, {
      filterKey: WORKFLOW_FILTER,
      type: 'id',
      label: 'Status',
      multiple: false,
      subEntityTypes,
      elementsForFilterValuesSearch: [ENTITY_TYPE_STATUS_TEMPLATE],
    });
  }
};

const handleRemoveSpecialKeysFromFilterDefinitionsMap = (filterDefinitionsMap: Map<string, FilterDefinition>, type: string, isNotEnterpriseEdition: boolean) => {
  // Shared with (remove if not EE)
  if (isNotEnterpriseEdition) {
    filterDefinitionsMap.delete(INPUT_GRANTED_REFS);
  }
  // Entity type (only available for abstract entity types)
  if (!isAbstract(type) && !isBasicRelationship(type)) {
    filterDefinitionsMap.delete(TYPE_FILTER);
  }
};

const completeFilterDefinitionsMapForTypeAndSubtypes = (filterDefinitionsMap: Map<string, FilterDefinition>, type: string) => {
  const subTypes = schemaTypesDefinition.hasChildren(type) ? schemaTypesDefinition.get(type) : []; // fetch the subtypes
  completeFilterDefinitionMapForType(filterDefinitionsMap, type, subTypes); // add attributes and relations refs of type
  completeFilterDefinitionMapWithSpecialKeys(type, filterDefinitionsMap, subTypes.concat([type])); // add or remove some special keys
  if (subTypes.length > 0) { // handle the filter definitions of the subtypes
    subTypes.forEach((subType) => {
      completeFilterDefinitionsMapForTypeAndSubtypes(filterDefinitionsMap, subType);
    });
  }
};

export const generateFilterKeysSchema = async () => {
  const filterKeysSchema: Map<string, Map<string, FilterDefinition>> = new Map();
  const context = executionContext('filterKeysSchema');
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const isNotEnterpriseEdition = isEmptyField(settings.enterprise_edition);
  // A. build filterKeysSchema map for each entity type
  const registeredTypes = schemaAttributesDefinition.getRegisteredTypes();
  registeredTypes.forEach((type) => {
    const filterDefinitionsMap: Map<string, FilterDefinition> = new Map(); // map that will contain the filterKeys schema for the entity type
    completeFilterDefinitionsMapForTypeAndSubtypes(filterDefinitionsMap, type);
    handleRemoveSpecialKeysFromFilterDefinitionsMap(filterDefinitionsMap, type, isNotEnterpriseEdition);
    filterKeysSchema.set(type, filterDefinitionsMap);
  });
  // B. add special types
  // connectedToId special key (for instance triggers)
  filterKeysSchema.set('Instance', new Map([[CONNECTED_TO_INSTANCE_FILTER, {
    filterKey: CONNECTED_TO_INSTANCE_FILTER,
    type: 'id',
    label: 'Related entity',
    multiple: true,
    subEntityTypes: [],
    elementsForFilterValuesSearch: [ABSTRACT_STIX_CORE_OBJECT],
  }]]));
  // representative (for streams, triggers, playbooks)
  filterKeysSchema.set('Stix-Filtering', new Map([[REPRESENTATIVE_FILTER, {
    filterKey: REPRESENTATIVE_FILTER,
    type: 'string',
    label: 'Representation',
    multiple: true,
    subEntityTypes: [],
    elementsForFilterValuesSearch: [],
  }]]));
  // C. transform the filterKeysSchema map in { key, values }[]
  const flattenFilterKeysSchema: { entity_type: string, filters_schema: { filterDefinition: FilterDefinition, filterKey: string }[] }[] = [];
  filterKeysSchema.forEach((filtersMap, entity_type) => {
    const filters_schema: { filterDefinition: FilterDefinition, filterKey: string }[] = [];
    filtersMap.forEach((filterDefinition, filterKey) => {
      filters_schema.push({ filterDefinition, filterKey });
    });
    flattenFilterKeysSchema.push({
      filters_schema,
      entity_type
    });
  });
  return flattenFilterKeysSchema;
};
