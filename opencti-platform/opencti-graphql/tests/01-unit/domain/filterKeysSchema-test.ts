import { describe, expect, it } from 'vitest';
import { generateFilterKeysSchema } from '../../../src/domain/filterKeysSchema';
import {
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ENTITY_TYPE_CONTAINER,
  ENTITY_TYPE_LOCATION,
  INPUT_CREATED_BY,
  INPUT_KILLCHAIN,
  INPUT_LABELS
} from '../../../src/schema/general';
import { ENTITY_TYPE_LABEL } from '../../../src/schema/stixMetaObject';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_MALWARE, ENTITY_TYPE_VULNERABILITY } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_TRIGGER } from '../../../src/modules/notification/notification-types';
import { ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_HASHED_OBSERVABLE_STIX_FILE, ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE } from '../../../src/schema/stixCyberObservable';
import { ENTITY_TYPE_CONTAINER_CASE } from '../../../src/modules/case/case-types';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../../../src/modules/grouping/grouping-types';
import { ALIAS_FILTER, CONTEXT_OBJECT_LABEL_FILTER, INSTANCE_REGARDING_OF } from '../../../src/utils/filtering/filtering-constants';
import { ENTITY_TYPE_HISTORY } from '../../../src/schema/internalObject';

describe('Filter keys schema generation testing', async () => {
  const filterKeysSchemaArray = await generateFilterKeysSchema();
  const filterKeysSchema = new Map(filterKeysSchemaArray
    .map((n) => [
      n.entity_type,
      new Map(n.filters_schema.map((m) => [m.filterKey, m.filterDefinition]))
    ]));
  it('should generate a filter keys schema for filterable attributes only', () => {
    const stixCoreObjectFilterDefinitionMap = filterKeysSchema.get(ABSTRACT_STIX_CORE_OBJECT);
    expect(stixCoreObjectFilterDefinitionMap?.get('name')?.filterKey).toEqual('name'); // filterable attribute
    expect(stixCoreObjectFilterDefinitionMap?.get('content_mapping')).toEqual(undefined); // not filterable attribute
  });
  it('should construct correct filter definition for vocabulary string attributes', () => {
    // 'report_types' attribute (for Report entity type)
    const filterDefinition = filterKeysSchema.get(ENTITY_TYPE_CONTAINER_REPORT)?.get('report_types');
    expect(filterDefinition?.filterKey).toEqual('report_types');
    expect(filterDefinition?.type).toEqual('vocabulary');
    expect(filterDefinition?.label).toEqual('Report types');
    expect(filterDefinition?.multiple).toEqual(true);
    expect(filterDefinition?.elementsForFilterValuesSearch.length).toEqual(1);
    expect(filterDefinition?.elementsForFilterValuesSearch[0]).toEqual('report_types_ov');
    expect(filterDefinition?.subEntityTypes.length).toEqual(1);
    expect(filterDefinition?.subEntityTypes[0]).toEqual(ENTITY_TYPE_CONTAINER_REPORT);
  });
  it('should construct correct filter definition for relations ref', () => {
    // objectLabel ref
    let filterDefinition = filterKeysSchema.get(ENTITY_TYPE_MALWARE)?.get(INPUT_LABELS);
    expect(filterDefinition?.filterKey).toEqual(INPUT_LABELS);
    expect(filterDefinition?.type).toEqual('id');
    expect(filterDefinition?.multiple).toEqual(true);
    expect(filterDefinition?.elementsForFilterValuesSearch.length).toEqual(1);
    expect(filterDefinition?.elementsForFilterValuesSearch[0]).toEqual(ENTITY_TYPE_LABEL);
    // createdBy ref
    filterDefinition = filterKeysSchema.get(ENTITY_TYPE_MALWARE)?.get(INPUT_CREATED_BY);
    expect(filterDefinition?.filterKey).toEqual(INPUT_CREATED_BY);
    expect(filterDefinition?.type).toEqual('id');
    expect(filterDefinition?.multiple).toEqual(false);
    expect(filterDefinition?.elementsForFilterValuesSearch.length).toEqual(4);
  });
  it('should construct correct filter definition for enum string attributes', () => {
    const filterDefinition = filterKeysSchema.get(ENTITY_TYPE_TRIGGER)?.get('trigger_type');
    expect(filterDefinition?.filterKey).toEqual('trigger_type');
    expect(filterDefinition?.type).toEqual('enum');
    expect(filterDefinition?.multiple).toEqual(false);
    expect(filterDefinition?.elementsForFilterValuesSearch.length).toEqual(2);
    expect((filterDefinition?.elementsForFilterValuesSearch ?? []).includes('digest')).toBeTruthy();
  });
  it('should construct correct filter definition for short and text string attributes', () => {
    // 'name' attribute
    let filterDefinition = filterKeysSchema.get(ENTITY_TYPE_CONTAINER_REPORT)?.get('name');
    expect(filterDefinition?.filterKey).toEqual('name');
    expect(filterDefinition?.type).toEqual('string');
    expect(filterDefinition?.elementsForFilterValuesSearch.length).toEqual(0);
    // 'description' attribute
    filterDefinition = filterKeysSchema.get(ENTITY_TYPE_CONTAINER_REPORT)?.get('description');
    expect(filterDefinition?.filterKey).toEqual('description');
    expect(filterDefinition?.type).toEqual('text');
    expect(filterDefinition?.elementsForFilterValuesSearch.length).toEqual(0);
  });
  it('should construct correct filter definition for boolean attributes', () => {
    const filterDefinition = filterKeysSchema.get(ENTITY_TYPE_NOTIFICATION)?.get('is_read');
    expect(filterDefinition?.filterKey).toEqual('is_read');
    expect(filterDefinition?.type).toEqual('boolean');
    expect(filterDefinition?.elementsForFilterValuesSearch.length).toEqual(0);
  });
  it('should construct correct filter definition for date attributes', () => {
    const filterDefinition = filterKeysSchema.get(ENTITY_TYPE_MALWARE)?.get('created_at');
    expect(filterDefinition?.filterKey).toEqual('created_at');
    expect(filterDefinition?.type).toEqual('date');
    expect(filterDefinition?.elementsForFilterValuesSearch.length).toEqual(0);
  });
  it('should construct correct filter definition for numeric attributes', () => {
    // 'confidence' attribute (integer)
    let filterDefinition = filterKeysSchema.get(ENTITY_TYPE_MALWARE)?.get('confidence');
    expect(filterDefinition?.filterKey).toEqual('confidence');
    expect(filterDefinition?.type).toEqual('integer');
    expect(filterDefinition?.elementsForFilterValuesSearch.length).toEqual(0);
    // 'x_opencti_cvss_base_score' attribute (float)
    filterDefinition = filterKeysSchema.get(ENTITY_TYPE_VULNERABILITY)?.get('x_opencti_cvss_base_score');
    expect(filterDefinition?.filterKey).toEqual('x_opencti_cvss_base_score');
    expect(filterDefinition?.type).toEqual('float');
    expect(filterDefinition?.elementsForFilterValuesSearch.length).toEqual(0);
    // 'size' attribute (long)
    filterDefinition = filterKeysSchema.get(ENTITY_HASHED_OBSERVABLE_STIX_FILE)?.get('size');
    expect(filterDefinition?.filterKey).toEqual('size');
    expect(filterDefinition?.type).toEqual('integer');
    expect(filterDefinition?.elementsForFilterValuesSearch.length).toEqual(0);
  });
  it('should construct correct filter definition for standard object attributes', () => {
    // 'MD5 hash' for observables
    let filterDefinition = filterKeysSchema.get(ABSTRACT_STIX_CYBER_OBSERVABLE)?.get('hashes.MD5');
    expect(filterDefinition?.filterKey).toEqual('hashes.MD5');
    expect(filterDefinition?.type).toEqual('string');
    expect(filterDefinition?.label).toEqual('MD5');
    expect(filterDefinition?.elementsForFilterValuesSearch.length).toEqual(0);
    expect(filterDefinition?.subEntityTypes.length).toEqual(3);
    expect(filterDefinition?.subEntityTypes.includes(ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE)).toBeTruthy();
    expect(filterDefinition?.subEntityTypes.includes(ENTITY_HASHED_OBSERVABLE_ARTIFACT)).toBeTruthy();
    // 'LZJD hash' for observables (not filterable)
    filterDefinition = filterKeysSchema.get(ABSTRACT_STIX_CYBER_OBSERVABLE)?.get('hashes.LZJD');
    expect(filterDefinition).toBeUndefined(); // LZJD hash is not filterable
    // 'operation' for notifications (mapping attribute in a mapping attribute)
    filterDefinition = filterKeysSchema.get(ABSTRACT_STIX_CYBER_OBSERVABLE)?.get('notification_content.events.operation');
    expect(filterDefinition?.filterKey).toEqual('notification_content.events.operation');
    expect(filterDefinition?.type).toEqual('enum');
    expect(filterDefinition?.elementsForFilterValuesSearch.length).toEqual(3); // create, update, delete
  });
  it('should construct correct filter definition for nested object attributes', () => {
    // 'fromId' for relationships
    let filterDefinition = filterKeysSchema.get(ABSTRACT_STIX_CORE_RELATIONSHIP)?.get('fromId');
    expect(filterDefinition?.filterKey).toEqual('fromId');
    expect(filterDefinition?.type).toEqual('id');
    expect(filterDefinition?.label).toEqual('Source entity');
    expect(filterDefinition?.elementsForFilterValuesSearch.length).toEqual(1);
    expect(filterDefinition?.elementsForFilterValuesSearch[0]).toEqual(ABSTRACT_STIX_CORE_OBJECT);
    // 'toTypes' for relationships
    filterDefinition = filterKeysSchema.get(ABSTRACT_STIX_CORE_RELATIONSHIP)?.get('toTypes');
    expect(filterDefinition?.filterKey).toEqual('toTypes');
    expect(filterDefinition?.type).toEqual('string');
    expect(filterDefinition?.label).toEqual('Target type');
    expect(filterDefinition?.elementsForFilterValuesSearch.length).toEqual(0);
  });
  it('should construct correct filter definition for special filter keys', () => {
    // 'regardingOf' for stix core objects
    const filterDefinition = filterKeysSchema.get(ABSTRACT_STIX_CORE_OBJECT)?.get(INSTANCE_REGARDING_OF);
    expect(filterDefinition?.filterKey).toEqual(INSTANCE_REGARDING_OF);
    expect(filterDefinition?.type).toEqual('nested');
    expect(filterDefinition?.multiple).toEqual(true);
    expect(filterDefinition?.elementsForFilterValuesSearch.length).toEqual(0);
    expect(filterDefinition?.subFilters?.length).toEqual(2);
    expect(filterDefinition?.subFilters?.map((n) => n.filterKey).includes('relationship_type')).toBeTruthy();
  });
  it('should construct correct filter definition for abstract entity types', () => {
    // Containers
    let filterDefinition = filterKeysSchema.get(ENTITY_TYPE_CONTAINER)?.get(INPUT_CREATED_BY);
    expect(filterDefinition?.subEntityTypes.length).toEqual(12); // 11 entity types that are containers + 2 abstract types that are containers ('Container' and 'Case')
    expect(filterDefinition?.subEntityTypes.includes(ENTITY_TYPE_CONTAINER)).toBeTruthy();
    expect(filterDefinition?.subEntityTypes.includes(ENTITY_TYPE_CONTAINER_CASE)).toBeTruthy();
    expect(filterDefinition?.subEntityTypes.includes(ENTITY_TYPE_CONTAINER_GROUPING)).toBeTruthy();
    filterDefinition = filterKeysSchema.get(ENTITY_TYPE_CONTAINER)?.get('name');
    expect(filterDefinition?.subEntityTypes.length).toEqual(8); // 7 entity types that are containers and have a name + abstract type 'Case'
    expect(filterDefinition?.subEntityTypes.includes(ENTITY_TYPE_CONTAINER)).toBeFalsy();
    expect(filterDefinition?.subEntityTypes.includes(ENTITY_TYPE_CONTAINER_CASE)).toBeTruthy();
    expect(filterDefinition?.subEntityTypes.includes(ENTITY_TYPE_CONTAINER_GROUPING)).toBeTruthy();
    filterDefinition = filterKeysSchema.get(ENTITY_TYPE_CONTAINER_CASE)?.get(INPUT_CREATED_BY);
    expect(filterDefinition?.subEntityTypes.length).toEqual(5); // 4 entity types that are cases + 'Case' abstract type
    // Stix Core Objects
    filterDefinition = filterKeysSchema.get(ABSTRACT_STIX_CORE_OBJECT)?.get(INPUT_KILLCHAIN);
    expect(filterDefinition?.subEntityTypes.length).toEqual(5); // Attack-Pattern, Infrastructure, Malware, Tool, Indicator
    expect(filterDefinition?.subEntityTypes.includes(ENTITY_TYPE_ATTACK_PATTERN)).toBeTruthy();
    // Location
    filterDefinition = filterKeysSchema.get(ENTITY_TYPE_LOCATION)?.get(INPUT_CREATED_BY);
    expect(filterDefinition?.subEntityTypes.length).toEqual(6); // 5 locations + abstract type 'Location'
    // Stix Core Relationships
    filterDefinition = filterKeysSchema.get(ABSTRACT_STIX_CORE_RELATIONSHIP)?.get('fromId');
    expect(filterDefinition?.subEntityTypes.length).toEqual(49); // 48 stix core relationship types + abstract type 'stix-core-relationships'
    // Stix Cyber Observables
    filterDefinition = filterKeysSchema.get(ABSTRACT_STIX_CYBER_OBSERVABLE)?.get('x_opencti_score'); // attribute existing for all the observables
    filterDefinition = filterKeysSchema.get(ABSTRACT_STIX_CYBER_OBSERVABLE)?.get(INPUT_LABELS); // ref existing for all the observables
    expect(filterDefinition?.subEntityTypes.length).toEqual(30); // 29 observables + abstract type 'Stix-Cyber-Observable'
  });
  it('should includes the filters associated to the attributes of the History entity type', () => {
    let filterDefinition = filterKeysSchema.get(ENTITY_TYPE_HISTORY)?.get(CONTEXT_OBJECT_LABEL_FILTER);
    expect(filterDefinition?.type).toEqual('id');
    filterDefinition = filterKeysSchema.get(ENTITY_TYPE_HISTORY)?.get('event_type');
    expect(filterDefinition?.type).toEqual('enum');
    filterDefinition = filterKeysSchema.get(ENTITY_TYPE_HISTORY)?.get('report_types');
    expect(filterDefinition).toBeUndefined();
  });
  it('should includes the filter definitions of the subtypes', () => {
    let filterDefinition = filterKeysSchema.get(ABSTRACT_STIX_CORE_OBJECT)?.get(ALIAS_FILTER);
    expect(filterDefinition?.type).toEqual('string');
    filterDefinition = filterKeysSchema.get(ABSTRACT_STIX_CORE_OBJECT)?.get('indicator_types');
    expect(filterDefinition?.type).toEqual('vocabulary');
  });
});
