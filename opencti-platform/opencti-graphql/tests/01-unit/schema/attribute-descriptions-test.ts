import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { registerModules } from '../../../src/composition-root';
import { ATTRIBUTE_DESCRIPTIONS, ATTRIBUTE_DESCRIPTIONS_BY_TYPE, isDescribedType, resolveAttributeDescription } from '../../../src/schema/attribute-descriptions';
import { schemaAttributesDefinition } from '../../../src/schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../../src/schema/schema-relationsRef';
import type { VocabAttribute } from '../../../src/schema/attribute-definition';
import { ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';
import { INTERNAL_ATTRIBUTES } from '../../../src/domain/attribute-utils';
import { RELATION_TARGETS } from '../../../src/schema/stixCoreRelationship';
import { ENTITY_TYPE_EVENT } from '../../../src/modules/event/event-types';
import { ENTITY_TYPE_MALWARE_ANALYSIS } from '../../../src/modules/malwareAnalysis/malwareAnalysis-types';
import { ENTITY_TYPE_SECURITY_COVERAGE } from '../../../src/modules/securityCoverage/securityCoverage-types';
import { ENTITY_TYPE_SECURITY_COVERAGE_RESULT } from '../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-types';
import { ENTITY_TYPE_WORKFLOW_DEFINITION } from '../../../src/modules/workflow/types/workflow-types';
import { ENTITY_DOMAIN_NAME, ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE, ENTITY_MEDIA_CONTENT, ENTITY_SOFTWARE, ENTITY_SSH_KEY } from '../../../src/schema/stixCyberObservable';
import { ENTITY_TYPE_KILL_CHAIN_PHASE, ENTITY_TYPE_LABEL, ENTITY_TYPE_MARKING_DEFINITION } from '../../../src/schema/stixMetaObject';

registerModules();

// Every attribute and ref of the described types, with their type
const describedFields = () => schemaAttributesDefinition.getRegisteredTypes().filter(isDescribedType).flatMap((type) => {
  const attributes = Array.from(schemaAttributesDefinition.getAttributes(type).values())
    .filter((attribute) => !INTERNAL_ATTRIBUTES.includes(attribute.name));
  const refs: { name: string; description?: string }[] = schemaRelationsRefDefinition.getRelationsRef(type);
  return [...attributes, ...refs].map((field) => ({ type, field }));
});

describe('resolveAttributeDescription', () => {
  it('should use the description of the definition first', () => {
    expect(resolveAttributeDescription(ENTITY_TYPE_CONTAINER_NOTE, { name: 'content', description: 'Explicit' })).toEqual('Explicit');
  });

  it('should use the override of the type before the dictionary', () => {
    expect(resolveAttributeDescription(ENTITY_TYPE_CONTAINER_NOTE, { name: 'content' })).toEqual(ATTRIBUTE_DESCRIPTIONS_BY_TYPE[ENTITY_TYPE_CONTAINER_NOTE].content);
    expect(resolveAttributeDescription(ENTITY_TYPE_CONTAINER_REPORT, { name: 'content' })).toEqual(ATTRIBUTE_DESCRIPTIONS.content);
    // content is plain text in a Media-Content
    expect(resolveAttributeDescription(ENTITY_MEDIA_CONTENT, { name: 'content' })).toEqual(ATTRIBUTE_DESCRIPTIONS_BY_TYPE[ENTITY_MEDIA_CONTENT].content);
    // start_time is the validity of a relationship, but the start of an event
    expect(resolveAttributeDescription(RELATION_TARGETS, { name: 'start_time' })).toEqual(ATTRIBUTE_DESCRIPTIONS.start_time);
    expect(resolveAttributeDescription(ENTITY_TYPE_EVENT, { name: 'start_time' })).toEqual(ATTRIBUTE_DESCRIPTIONS_BY_TYPE[ENTITY_TYPE_EVENT].start_time);
    // resultOf lists the results of a coverage, but points a result to its parent coverage
    expect(resolveAttributeDescription(ENTITY_TYPE_SECURITY_COVERAGE, { name: 'resultOf' })).toEqual(ATTRIBUTE_DESCRIPTIONS_BY_TYPE[ENTITY_TYPE_SECURITY_COVERAGE].resultOf);
    expect(resolveAttributeDescription(ENTITY_TYPE_SECURITY_COVERAGE_RESULT, { name: 'resultOf' }))
      .toEqual(ATTRIBUTE_DESCRIPTIONS_BY_TYPE[ENTITY_TYPE_SECURITY_COVERAGE_RESULT].resultOf);
    // version is only described for a malware analysis, not shared with the other types
    expect(resolveAttributeDescription(ENTITY_TYPE_MALWARE_ANALYSIS, { name: 'version' })).toEqual(ATTRIBUTE_DESCRIPTIONS_BY_TYPE[ENTITY_TYPE_MALWARE_ANALYSIS].version);
    expect(ATTRIBUTE_DESCRIPTIONS.version).toBeUndefined();
    // version is the version of a software, but the X.509 encoding of a certificate
    expect(resolveAttributeDescription(ENTITY_SOFTWARE, { name: 'version' })).toEqual(ATTRIBUTE_DESCRIPTIONS_BY_TYPE[ENTITY_SOFTWARE].version);
    expect(resolveAttributeDescription(ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE, { name: 'version' }))
      .toEqual(ATTRIBUTE_DESCRIPTIONS_BY_TYPE[ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE].version);
    // value is the text of a label, but the value of an observable
    expect(resolveAttributeDescription(ENTITY_TYPE_LABEL, { name: 'value' })).toEqual(ATTRIBUTE_DESCRIPTIONS_BY_TYPE[ENTITY_TYPE_LABEL].value);
    expect(resolveAttributeDescription(ENTITY_DOMAIN_NAME, { name: 'value' })).toEqual(ATTRIBUTE_DESCRIPTIONS.value);
    // created is set by the author of an entity, but is the generation date of an SSH key, with no default
    expect(resolveAttributeDescription(ENTITY_TYPE_MALWARE_ANALYSIS, { name: 'created' })).toEqual(ATTRIBUTE_DESCRIPTIONS.created);
    expect(resolveAttributeDescription(ENTITY_SSH_KEY, { name: 'created' })).toEqual(ATTRIBUTE_DESCRIPTIONS_BY_TYPE[ENTITY_SSH_KEY].created);
    // x_opencti_order is the restriction level of a marking, but the position of a kill chain phase
    expect(resolveAttributeDescription(ENTITY_TYPE_MARKING_DEFINITION, { name: 'x_opencti_order' }))
      .toEqual(ATTRIBUTE_DESCRIPTIONS_BY_TYPE[ENTITY_TYPE_MARKING_DEFINITION].x_opencti_order);
    expect(resolveAttributeDescription(ENTITY_TYPE_KILL_CHAIN_PHASE, { name: 'x_opencti_order' }))
      .toEqual(ATTRIBUTE_DESCRIPTIONS_BY_TYPE[ENTITY_TYPE_KILL_CHAIN_PHASE].x_opencti_order);
  });

  it('should return null for an attribute without description', () => {
    expect(resolveAttributeDescription(ENTITY_TYPE_CONTAINER_REPORT, { name: 'undescribed_attribute' })).toBeNull();
  });

  it('should not describe from the dictionary the types it was not written for', () => {
    // content is the HTML of a container, but JSON in a workflow definition
    expect(resolveAttributeDescription(ENTITY_TYPE_WORKFLOW_DEFINITION, { name: 'content' })).toBeNull();
    // the author of a workflow definition is a user, not an identity
    expect(resolveAttributeDescription(ENTITY_TYPE_WORKFLOW_DEFINITION, { name: 'createdBy' })).toBeNull();
    // the definition still wins on any type
    expect(resolveAttributeDescription(ENTITY_TYPE_WORKFLOW_DEFINITION, { name: 'content', description: 'Explicit' })).toEqual('Explicit');
  });

  it('should describe every attribute and ref of the described types', () => {
    const undescribed = describedFields()
      .filter(({ type, field }) => !resolveAttributeDescription(type, field))
      .map(({ type, field }) => `${type}.${field.name}`);
    // A new attribute of a STIX Domain Object, observable, relationship, sighting or meta object needs a description in src/schema/attribute-descriptions.ts
    expect(undescribed).toEqual([]);
  });

  it('should name the vocabulary category of every vocabulary attribute', () => {
    // Its values are listed by the vocabularies query: a client needs the category to look them up
    const unnamed = describedFields()
      .filter(({ field }) => 'format' in field && field.format === 'vocabulary')
      .filter(({ type, field }) => !resolveAttributeDescription(type, field)?.includes((field as VocabAttribute).vocabularyCategory))
      .map(({ type, field }) => `${type}.${field.name}: ${(field as VocabAttribute).vocabularyCategory}`);
    expect(unnamed).toEqual([]);
  });

  it('should only hold descriptions of existing attributes and refs', () => {
    const fields = describedFields();
    const usedNames = new Set(fields.map(({ field }) => field.name));
    // A key matching no attribute is a typo or a removed field
    expect(Object.keys(ATTRIBUTE_DESCRIPTIONS).filter((name) => !usedNames.has(name))).toEqual([]);
    const unknownOverrides = Object.entries(ATTRIBUTE_DESCRIPTIONS_BY_TYPE).flatMap(([type, overrides]) => Object.keys(overrides)
      .filter((name) => !fields.some((used) => used.type === type && used.field.name === name))
      .map((name) => `${type}.${name}`));
    expect(unknownOverrides).toEqual([]);
  });

  it('should only share the descriptions of names used by several types', () => {
    // A name described for a single type belongs to its override: in the shared dictionary, a new
    // attribute reusing the name on another type would silently inherit a text written for the first one
    const fields = describedFields();
    const singleUse = Object.keys(ATTRIBUTE_DESCRIPTIONS).filter((name) => {
      const types = new Set(fields.filter(({ type, field }) => field.name === name && !ATTRIBUTE_DESCRIPTIONS_BY_TYPE[type]?.[name]).map(({ type }) => type));
      return types.size < 2;
    });
    expect(singleUse).toEqual([]);
  });
});
