import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { schemaTypesDefinition } from '../schema/schema-types';
import type {
  AttributeDefinition,
  EnumAttribute,
  IdAttribute,
  NestedObjectAttribute,
  NumericAttribute,
  RefAttribute,
  StringAttribute,
  VocabAttribute
} from '../schema/attribute-definition';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { isStixCoreObject } from '../schema/stixCoreObject';
import { ALIAS_FILTER, COMPUTED_RELIABILITY_FILTER, INSTANCE_REGARDING_OF, TYPE_FILTER, WORKFLOW_FILTER } from '../utils/filtering/filtering-constants';
import { INPUT_GRANTED_REFS, isAbstract } from '../schema/general';
import { getEntityFromCache } from '../database/cache';
import type { BasicStoreSettings } from '../types/settings';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_STATUS_TEMPLATE } from '../schema/internalObject';
import { isEmptyField } from '../database/utils';
import { ENTITY_HASHED_OBSERVABLE_ARTIFACT } from '../schema/stixCyberObservable';
import { isStixObjectAliased } from '../schema/stixDomainObject';
import { ENTITY_TYPE_MALWARE_ANALYSIS } from '../modules/malwareAnalysis/malwareAnalysis-types';
import { isBasicRelationship } from '../schema/stixRelationship';

type FilterDefinition = {
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

const completeFilterDefinitionMapWithNestedAttribute = (
  attributesMapWithFilterDefinition: Map<string, FilterDefinition>, // map in construction
  nestedAttributeDefinition: NestedObjectAttribute, // nested attribute to study
  types: string[], // entity types to apply
) => {
  const { mappings } = nestedAttributeDefinition;
  mappings.forEach((mappingAttributeDefinition) => {
    if (mappingAttributeDefinition.isFilterable) {
      if (mappingAttributeDefinition.type === 'object' && ['nested', 'standard'].includes(mappingAttributeDefinition.format)) { // case 1: nested attribute
        throw Error('A nested attribute can\'t contain a nested attribute'); // not supported for the moment
      } else if (mappingAttributeDefinition.associatedFilterKeys) { // case 2: not nested attribute and associatedFilterKeys is set
        // the keys to add are the ones in associatedFilterKeys
        mappingAttributeDefinition.associatedFilterKeys.forEach(({ key, label }) => {
          attributesMapWithFilterDefinition.set(
            key,
            buildFilterDefinitionFromAttributeDefinition({ ...mappingAttributeDefinition, name: key, label }, types),
          );
        });
      } else { // case 3: not nested attribute and the key to add is composed with the attribute name and the mapping attribute name
        const composedMappingName = `${nestedAttributeDefinition.name}.${mappingAttributeDefinition.name}`;
        attributesMapWithFilterDefinition.set(
          composedMappingName,
          buildFilterDefinitionFromAttributeDefinition({ ...mappingAttributeDefinition, name: composedMappingName }, types),
        );
      }
    }
  });
};

const completeFilterDefinitionMapWithElement = (
  filterKeyDefinitionMap: Map<string, FilterDefinition>,
  type: string,
  elementName: string,
  elementDefinition: AttributeDefinition | RefAttribute,
  elementDefinitionType: string, // 'attribute' or 'relationRef'
) => {
  const filterDefinition = filterKeyDefinitionMap.get(elementName);
  if (!filterDefinition) { // case 1.2.2: the attribute is in the type but not in the map
    const newFilterDefinition = elementDefinitionType === 'attribute'
      ? buildFilterDefinitionFromAttributeDefinition(elementDefinition as AttributeDefinition, [type])
      : buildFilterDefinitionFromRelationRefDefinition(elementDefinition as RefAttribute, [type]);
    filterKeyDefinitionMap.set( // add it in the map
      elementName,
      newFilterDefinition,
    );
  } else if (filterDefinition && !filterDefinition.subEntityTypes.includes(type)) { // 1.2.1 the filter definition is in the map but the type is not in the subEntityTypes
    filterKeyDefinitionMap.set(
      elementName,
      { ...filterDefinition, subEntityTypes: filterDefinition.subEntityTypes.concat([type]) }, // add type in subEntityTypes of the filter definition
    );
  }
};

const completeFilterDefinitionMapForType = (
  filterDefinitionMap: Map<string, FilterDefinition>, // filter definition map to complete
  type: string, // type whose attributes and relations refs to study (eventually add them in the map or complete subEntityTypes)
) => {
  // 01. add the attributes
  const attributesMap = schemaAttributesDefinition.getAttributes(type);
  attributesMap.forEach((attributeDefinition, attributeName) => {
    if (attributeDefinition.isFilterable) { // if it is filterable
      if (attributeDefinition.type === 'object' && ['nested', 'standard'].includes(attributeDefinition.format)) { // case 1.1: attribute with mappings
        completeFilterDefinitionMapWithNestedAttribute(filterDefinitionMap, attributeDefinition as NestedObjectAttribute, [type]);
      } else { // case 1.2: not nested attribute
        completeFilterDefinitionMapWithElement(filterDefinitionMap, type, attributeName, attributeDefinition, 'attribute');
      }
    }
  });
  // 02. add the relation refs
  if (schemaRelationsRefDefinition.getRegisteredTypes().includes(type)) {
    const relationRefs = schemaRelationsRefDefinition.getRelationsRef(type);
    relationRefs.forEach((ref) => {
      if (ref.isFilterable) {
        completeFilterDefinitionMapWithElement(filterDefinitionMap, type, ref.name, ref, 'relationRef');
      }
    });
  }
};

const completeFilterDefinitionMapWithSpecialKeys = (
  type: string,
  filterDefinitionsMap: Map<string, FilterDefinition>, // filter definition map to complete
  subEntityTypes: string[],
  isNotEnterpriseEdition: boolean,
) => {
  if (isStixCoreObject(type)) {
    // In regards of (exist relationship of the given relationship types for the given entities)
    filterDefinitionsMap.set('regardingOf', {
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
    // Entity type (only available for abstract entity types)
    if (!isAbstract(type) && !isBasicRelationship(type)) {
      filterDefinitionsMap.delete(TYPE_FILTER);
    }
    // Shared with (remove if not EE)
    if (isNotEnterpriseEdition) {
      filterDefinitionsMap.delete(INPUT_GRANTED_REFS);
    }
  }
};

export const generateFilterKeysSchema = async () => {
  const filterKeysSchema: Map<string, Map<string, FilterDefinition>> = new Map();
  const context = executionContext('filterKeysSchema');
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const isNotEnterpriseEdition = isEmptyField(settings.enterprise_edition);
  // A. build filterKeysSchema map
  const registeredTypes = schemaAttributesDefinition.getRegisteredTypes();
  registeredTypes.forEach((type) => {
    const filterDefinitionsMap: Map<string, FilterDefinition> = new Map(); // map that will contains the filterKeys schema for the entity type
    const subTypes = schemaTypesDefinition.hasChildren(type) ? schemaTypesDefinition.get(type) : []; // fetch the subtypes
    // 01. add attributes and relations refs of type
    completeFilterDefinitionMapForType(filterDefinitionsMap, type);
    // 02. add or remove some special keys
    completeFilterDefinitionMapWithSpecialKeys(type, filterDefinitionsMap, subTypes.concat([type]), isNotEnterpriseEdition);
    // 03. handle the attributes and relations refs of the subtypes
    if (subTypes.length > 0) {
      subTypes.forEach((subType) => completeFilterDefinitionMapForType(filterDefinitionsMap, subType));
    }
    // 04. set the filter definition in the filter schema
    filterKeysSchema.set(type, filterDefinitionsMap);
  });
  // B. transform the filterKeysSchema map in { key, values }[]
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
