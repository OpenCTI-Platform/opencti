import { describe, expect, it } from 'vitest';
import { isRelationConsistent } from '../../../src/utils/modelConsistency';
import {
  createdBy,
  externalReferences,
  INPUT_BELONGS_TO,
  INPUT_BODY_MULTIPART,
  INPUT_BODY_RAW,
  INPUT_CHILD,
  INPUT_CONTAINS,
  INPUT_CONTENT,
  INPUT_CREATOR_USER,
  INPUT_DST,
  INPUT_DST_PAYLOAD,
  INPUT_ENCAPSULATED_BY,
  INPUT_ENCAPSULATES,
  INPUT_FROM,
  INPUT_IMAGE,
  INPUT_OPENED_CONNECTION,
  INPUT_OPERATING_SYSTEM,
  INPUT_PARENT,
  INPUT_PARENT_DIRECTORY,
  INPUT_RAW_EMAIL,
  INPUT_RESOLVES_TO,
  INPUT_SAMPLE,
  INPUT_SENDER,
  INPUT_SERVICE_DLL,
  INPUT_SRC,
  INPUT_SRC_PAYLOAD,
  INPUT_TO,
  INPUT_VALUES,
  objectAssignee,
  objectLabel,
  objectMarking,
  RELATION_CONTENT,
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
  RELATION_OPERATING_SYSTEM
} from '../../../src/schema/stixRefRelationship';
import {
  ENTITY_AUTONOMOUS_SYSTEM,
  ENTITY_DIRECTORY,
  ENTITY_DOMAIN_NAME,
  ENTITY_EMAIL_ADDR,
  ENTITY_EMAIL_MESSAGE,
  ENTITY_EMAIL_MIME_PART_TYPE,
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_IPV4_ADDR,
  ENTITY_IPV6_ADDR,
  ENTITY_MAC_ADDR,
  ENTITY_NETWORK_TRAFFIC,
  ENTITY_PROCESS,
  ENTITY_SOFTWARE,
  ENTITY_USER_ACCOUNT,
  ENTITY_WINDOWS_REGISTRY_KEY,
  ENTITY_WINDOWS_REGISTRY_VALUE_TYPE
} from '../../../src/schema/stixCyberObservable';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY
} from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_LABEL, ENTITY_TYPE_MARKING_DEFINITION } from '../../../src/schema/stixMetaObject';
import {
  isStixCoreRelationship,
  RELATION_COMMUNICATES_WITH,
  RELATION_CONSISTS_OF,
  RELATION_DERIVED_FROM,
  RELATION_DETECTS,
  RELATION_HOSTS,
  RELATION_INDICATES,
  RELATION_PART_OF,
  RELATION_RELATED_TO,
  RELATION_USES
} from '../../../src/schema/stixCoreRelationship';
import {
  ABSTRACT_INTERNAL_OBJECT,
  ABSTRACT_INTERNAL_RELATIONSHIP,
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_META_OBJECT,
  ABSTRACT_STIX_REF_RELATIONSHIP,
  ABSTRACT_STIX_RELATIONSHIP,
  ENTITY_TYPE_CONTAINER,
  ENTITY_TYPE_IDENTITY
} from '../../../src/schema/general';

import '../../../src/modules/index';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { isDateNumericOrBooleanAttribute, isJsonAttribute, isMultipleAttribute, isObjectAttribute, schemaAttributesDefinition } from '../../../src/schema/schema-attributes';
import { ENTITY_TYPE_ENTITY_SETTING } from '../../../src/modules/entitySetting/entitySetting-types';
import { ENTITY_TYPE_CHANNEL } from '../../../src/modules/channel/channel-types';
import { ENTITY_TYPE_INDICATOR } from '../../../src/modules/indicator/indicator-types';
import { stixRefsExtractor } from '../../../src/schema/stixEmbeddedRelationship';
import { generateStandardId } from '../../../src/schema/identifier';
import { schemaRelationsRefDefinition } from '../../../src/schema/schema-relationsRef';
import { confidence, created, entityType, xOpenctiStixIds } from '../../../src/schema/attribute-definition';
import { getParentTypes } from '../../../src/schema/schemaUtils';
import { ENTITY_TYPE_RULE } from '../../../src/schema/internalObject';
import { RELATION_MIGRATES } from '../../../src/schema/internalRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../src/schema/stixSightingRelationship';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { schemaRelationsTypesMapping } from '../../../src/domain/stixRelationship';

describe('Testing relation consistency', () => {
  it.concurrent.each([
    // CREATED_BY
    [RELATION_CREATED_BY, ENTITY_HASHED_OBSERVABLE_STIX_FILE, ENTITY_TYPE_IDENTITY_ORGANIZATION, true],
    [RELATION_CREATED_BY, ENTITY_HASHED_OBSERVABLE_STIX_FILE, ENTITY_HASHED_OBSERVABLE_STIX_FILE, false],
    [RELATION_CREATED_BY, ENTITY_TYPE_COURSE_OF_ACTION, ENTITY_TYPE_CAMPAIGN, false],
    // EXTERNAL_REF
    [RELATION_EXTERNAL_REFERENCE, ENTITY_HASHED_OBSERVABLE_STIX_FILE, ENTITY_TYPE_IDENTITY_ORGANIZATION, false],
    // LABEL
    [RELATION_OBJECT_LABEL, ENTITY_HASHED_OBSERVABLE_STIX_FILE, ENTITY_TYPE_LABEL, true],
    // MARKING
    [RELATION_OBJECT_MARKING, ENTITY_HASHED_OBSERVABLE_STIX_FILE, ENTITY_TYPE_MARKING_DEFINITION, true],
    [RELATION_OBJECT_MARKING, ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_MALWARE, false],
    [RELATION_OBJECT_MARKING, ENTITY_TYPE_CONTAINER_OPINION, ENTITY_TYPE_MALWARE, false],
    // OBS_CONTENT
    [RELATION_CONTENT, ENTITY_SOFTWARE, ENTITY_HASHED_OBSERVABLE_STIX_FILE, false],
    [RELATION_CONTENT, ENTITY_HASHED_OBSERVABLE_STIX_FILE, ENTITY_HASHED_OBSERVABLE_ARTIFACT, true],
    [RELATION_CONTENT, ENTITY_HASHED_OBSERVABLE_STIX_FILE, ENTITY_HASHED_OBSERVABLE_ARTIFACT, true],
    [RELATION_CONTENT, ENTITY_TYPE_CONTAINER_OBSERVED_DATA, ENTITY_HASHED_OBSERVABLE_STIX_FILE, false],
    // KILL_CHAIN
    [RELATION_KILL_CHAIN_PHASE, ENTITY_HASHED_OBSERVABLE_STIX_FILE, ENTITY_HASHED_OBSERVABLE_ARTIFACT, false],
    // OBJECT_REF
    [RELATION_OBJECT, ENTITY_TYPE_CONTAINER_OPINION, [
      ENTITY_TYPE_MALWARE,
      ENTITY_TYPE_CONTAINER_NOTE,
      ENTITY_TYPE_INCIDENT,
      ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
    ], true],
    [RELATION_OBJECT, ENTITY_HASHED_OBSERVABLE_STIX_FILE, [
      ENTITY_TYPE_MALWARE,
      ENTITY_TYPE_CONTAINER_NOTE,
      ENTITY_TYPE_INCIDENT,
      ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
    ], false],
    // MODULE
    // TODO This should work someday when we find a way of importing modules without breaking testing
    // [RELATION_BELONGS_TO, ENTITY_TYPE_CHANNEL, ENTITY_TYPE_IDENTITY_ORGANIZATION, false],
    // RELATIONSHIPS
    [RELATION_USES, ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_ATTACK_PATTERN, true],
    [RELATION_USES, ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_MALWARE, true],
    [RELATION_INDICATES, ENTITY_TYPE_INDICATOR, ENTITY_TYPE_MALWARE, true],
    [RELATION_DERIVED_FROM, ENTITY_TYPE_INDICATOR, ENTITY_TYPE_INDICATOR, true],
    [RELATION_RELATED_TO, ENTITY_TYPE_TOOL, ENTITY_TYPE_VULNERABILITY, true],
    [RELATION_USES, ENTITY_TYPE_INDICATOR, ENTITY_TYPE_MALWARE, false],
    [RELATION_USES, ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_VULNERABILITY, false],
    [RELATION_PART_OF, ENTITY_TYPE_IDENTITY, ENTITY_TYPE_IDENTITY, false],
    // TODO THIS SHOULD BE SUPPORTED
    [RELATION_DERIVED_FROM, ENTITY_TYPE_TOOL, ENTITY_TYPE_VULNERABILITY, false],
  ])(
    'Trying to create a relation of type %s from %s to %s',
    async (relType, fromType, toType, expected) => {
      const relationConsistency = await isRelationConsistent(
        testContext,
        ADMIN_USER,
        relType,
        { entity_type: fromType },
        Array.isArray(toType) ? toType.map((t) => ({ entity_type: t })) : { entity_type: toType }
      );
      expect(relationConsistency).toBe(expected);
    }
  );
});

describe('Testing schema types definition', () => {
  it('Parent types object testing', () => {
    expect(getParentTypes(ENTITY_TYPE_CONTAINER_REPORT).includes(ENTITY_TYPE_CONTAINER)).toBe(true);
    expect(getParentTypes(ENTITY_TYPE_CONTAINER_REPORT).includes(ABSTRACT_STIX_META_OBJECT)).toBe(false);

    expect(getParentTypes(ENTITY_TYPE_VULNERABILITY).includes(ABSTRACT_STIX_DOMAIN_OBJECT)).toBe(true);
    expect(getParentTypes(ENTITY_TYPE_VULNERABILITY).includes(ENTITY_TYPE_CONTAINER)).toBe(false);

    expect(getParentTypes(ENTITY_TYPE_LABEL).includes(ABSTRACT_STIX_META_OBJECT)).toBe(true);
    expect(getParentTypes(ENTITY_TYPE_LABEL).includes(ABSTRACT_INTERNAL_OBJECT)).toBe(false);

    expect(getParentTypes(ENTITY_TYPE_RULE).includes(ABSTRACT_INTERNAL_OBJECT)).toBe(true);
    expect(getParentTypes(ENTITY_TYPE_RULE).includes(ABSTRACT_STIX_CYBER_OBSERVABLE)).toBe(false);
  });
  it('Parent types relationship testing', () => {
    expect(getParentTypes(RELATION_MIGRATES).includes(ABSTRACT_INTERNAL_RELATIONSHIP)).toBe(true);
    expect(getParentTypes(RELATION_MIGRATES).includes(ABSTRACT_STIX_CORE_RELATIONSHIP)).toBe(false);

    expect(getParentTypes(RELATION_EXTERNAL_REFERENCE).includes(ABSTRACT_STIX_REF_RELATIONSHIP)).toBe(true);
    expect(getParentTypes(RELATION_EXTERNAL_REFERENCE).includes(ABSTRACT_STIX_CORE_RELATIONSHIP)).toBe(false);

    expect(getParentTypes(RELATION_HOSTS).includes(ABSTRACT_STIX_CORE_RELATIONSHIP)).toBe(true);
    expect(getParentTypes(RELATION_HOSTS).includes(ABSTRACT_INTERNAL_RELATIONSHIP)).toBe(false);

    expect(getParentTypes(RELATION_OPERATING_SYSTEM).includes(ABSTRACT_STIX_REF_RELATIONSHIP)).toBe(true);
    expect(getParentTypes(RELATION_OPERATING_SYSTEM).includes(ABSTRACT_STIX_CORE_RELATIONSHIP)).toBe(false);

    expect(getParentTypes(STIX_SIGHTING_RELATIONSHIP).includes(ABSTRACT_STIX_RELATIONSHIP)).toBe(true);
    expect(getParentTypes(STIX_SIGHTING_RELATIONSHIP).includes(ABSTRACT_STIX_REF_RELATIONSHIP)).toBe(false);
  });
  it('Relations testing', () => {
    expect(isStixCoreRelationship(ENTITY_TYPE_CONTAINER_REPORT)).toBe(false);
    expect(isStixCoreRelationship(ABSTRACT_STIX_CORE_RELATIONSHIP)).toBe(true);
    expect(isStixCoreRelationship(RELATION_DETECTS)).toBe(true);
    expect(isStixCoreRelationship('detects-false')).toBe(false);
  });
});

describe('Testing schema attributes definition', () => {
  it('Attributes type testing', () => {
    expect(isJsonAttribute('revoked')).toBe(false);
    expect(isObjectAttribute('bookmarks')).toBe(true);
    expect(isDateNumericOrBooleanAttribute('bookmarks')).toBe(false);
    expect(isDateNumericOrBooleanAttribute('attribute_order')).toBe(true);
    expect(isDateNumericOrBooleanAttribute('start_time')).toBe(true);
    expect(isDateNumericOrBooleanAttribute('platform_hidden_type')).toBe(true);
    expect(isMultipleAttribute(ENTITY_TYPE_ENTITY_SETTING, 'platform_hidden_type')).toBe(false);
    expect(isMultipleAttribute(ENTITY_TYPE_CHANNEL, 'channel_types')).toBe(true);
  });
  it('Attributes upsert testing', () => {
    const availableAttributes = Array.from(schemaAttributesDefinition.getAttributes(ENTITY_TYPE_CONTAINER_REPORT).values());
    const upsertAttributes = availableAttributes.filter((f) => f.upsert).map((f) => f.name).sort();
    const reportUpsertAttributes = schemaAttributesDefinition.getUpsertAttributeNames(ENTITY_TYPE_CONTAINER_REPORT).sort();
    expect(upsertAttributes).toStrictEqual(reportUpsertAttributes);
  });
  it('Attributes inheritance testing', () => {
    // Stix-Domain-Object
    expect(schemaAttributesDefinition.getAttributes(ABSTRACT_STIX_DOMAIN_OBJECT).get(entityType.name).name === entityType.name).toBe(true);
    expect(schemaAttributesDefinition.getAttributes(ABSTRACT_STIX_DOMAIN_OBJECT).get(xOpenctiStixIds.name).name === xOpenctiStixIds.name).toBe(true);
    expect(schemaAttributesDefinition.getAttributes(ABSTRACT_STIX_DOMAIN_OBJECT).get(confidence.name).name === confidence.name).toBe(true);
    // Report
    expect(schemaAttributesDefinition.getAttributes(ENTITY_TYPE_CONTAINER_REPORT).get('report_types').name === 'report_types').toBe(true);
    // Note
    expect(schemaAttributesDefinition.getAttributes(ENTITY_TYPE_CONTAINER_NOTE).get(created.name).mandatoryType === 'external').toBe(true);

    // Stix-Ref-Relationship
    expect(schemaAttributesDefinition.getAttributes(ABSTRACT_STIX_REF_RELATIONSHIP).get('start_time').name === 'start_time').toBe(true);
    expect(schemaAttributesDefinition.getAttributes(ABSTRACT_STIX_REF_RELATIONSHIP).get('stop_time').name === 'stop_time').toBe(true);
  });
});
describe('Testing schema relations ref definition', () => {
  it('Relations ref inheritance testing', () => {
    const relationsRefSDO = schemaRelationsRefDefinition.getRelationsRef(ABSTRACT_STIX_DOMAIN_OBJECT);
    const relationsRefReport = schemaRelationsRefDefinition.getRelationsRef(ENTITY_TYPE_CONTAINER_REPORT);
    expect(relationsRefSDO.some((relRefSDO) => relationsRefReport.includes(relRefSDO))).toBe(true);
    expect(relationsRefSDO.includes(objectAssignee)).toBe(false);
    expect(relationsRefReport.includes(objectAssignee)).toBe(true);

    expect(schemaRelationsRefDefinition.getRelationRef(ENTITY_TYPE_CONTAINER_REPORT, createdBy.inputName).inputName === createdBy.inputName).toBe(true);
    expect(schemaRelationsRefDefinition.getInputNames(ENTITY_TYPE_CONTAINER_REPORT).includes(objectMarking.inputName)).toBe(true);
    expect(schemaRelationsRefDefinition.getStixNames(ENTITY_TYPE_CONTAINER_REPORT).includes(objectLabel.stixName)).toBe(true);
    expect(schemaRelationsRefDefinition.isMultipleDatabaseName(ENTITY_TYPE_CONTAINER_REPORT, externalReferences.databaseName)).toBe(true);
    expect(schemaRelationsRefDefinition.convertDatabaseNameToInputName(ENTITY_TYPE_CONTAINER_REPORT, externalReferences.databaseName) === externalReferences.inputName).toBe(true);
    expect(schemaRelationsRefDefinition.convertStixNameToInputName(ENTITY_TYPE_CONTAINER_REPORT, externalReferences.stixName) === externalReferences.inputName).toBe(true);
  });
  it('Relations Cyber Observable testing', () => {
    let relationsRef = schemaRelationsRefDefinition.getRelationsRef(ENTITY_DIRECTORY);
    let [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_CONTAINS);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_DIRECTORY, ENTITY_DIRECTORY)).toBe(true);
    expect(relationRef.checker(ENTITY_DIRECTORY, ENTITY_DOMAIN_NAME)).toBe(false);

    relationsRef = schemaRelationsRefDefinition.getRelationsRef(ENTITY_DOMAIN_NAME);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_RESOLVES_TO);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_DIRECTORY, ENTITY_DOMAIN_NAME)).toBe(true);
    expect(relationRef.checker(ENTITY_DIRECTORY, ENTITY_HASHED_OBSERVABLE_STIX_FILE)).toBe(false);

    relationsRef = schemaRelationsRefDefinition.getRelationsRef(ENTITY_EMAIL_MESSAGE);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_FROM);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_EMAIL_MESSAGE, ENTITY_EMAIL_ADDR)).toBe(true);
    expect(relationRef.checker(ENTITY_EMAIL_MESSAGE, ENTITY_IPV4_ADDR)).toBe(false);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_SENDER);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_EMAIL_MESSAGE, ENTITY_EMAIL_ADDR)).toBe(true);
    expect(relationRef.checker(ENTITY_EMAIL_MESSAGE, ENTITY_IPV4_ADDR)).toBe(false);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_TO);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_EMAIL_MESSAGE, ENTITY_EMAIL_ADDR)).toBe(true);
    expect(relationRef.checker(ENTITY_EMAIL_MESSAGE, ENTITY_IPV4_ADDR)).toBe(false);

    relationsRef = schemaRelationsRefDefinition.getRelationsRef(ENTITY_EMAIL_ADDR);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_BELONGS_TO);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_EMAIL_ADDR, ENTITY_USER_ACCOUNT)).toBe(true);
    expect(relationRef.checker(ENTITY_EMAIL_ADDR, ENTITY_IPV4_ADDR)).toBe(false);

    relationsRef = schemaRelationsRefDefinition.getRelationsRef(ENTITY_EMAIL_MESSAGE);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_BODY_MULTIPART);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_EMAIL_MESSAGE, ENTITY_EMAIL_MIME_PART_TYPE)).toBe(true);
    expect(relationRef.checker(ENTITY_EMAIL_MESSAGE, ENTITY_IPV4_ADDR)).toBe(false);

    relationsRef = schemaRelationsRefDefinition.getRelationsRef(ENTITY_EMAIL_MESSAGE);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_RAW_EMAIL);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_EMAIL_MESSAGE, ENTITY_HASHED_OBSERVABLE_ARTIFACT)).toBe(true);
    expect(relationRef.checker(ENTITY_EMAIL_MESSAGE, ENTITY_IPV4_ADDR)).toBe(false);

    relationsRef = schemaRelationsRefDefinition.getRelationsRef(ENTITY_EMAIL_MIME_PART_TYPE);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_BODY_RAW);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_EMAIL_MIME_PART_TYPE, ENTITY_HASHED_OBSERVABLE_ARTIFACT)).toBe(true);
    expect(relationRef.checker(ENTITY_EMAIL_MIME_PART_TYPE, ENTITY_HASHED_OBSERVABLE_STIX_FILE)).toBe(true);
    expect(relationRef.checker(ENTITY_EMAIL_MIME_PART_TYPE, ENTITY_EMAIL_MESSAGE)).toBe(false);

    relationsRef = schemaRelationsRefDefinition.getRelationsRef(ENTITY_TYPE_MALWARE);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_SAMPLE);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_HASHED_OBSERVABLE_ARTIFACT)).toBe(true);
    expect(relationRef.checker(ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_IPV4_ADDR)).toBe(false);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_OPERATING_SYSTEM);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_SOFTWARE)).toBe(true);
    expect(relationRef.checker(ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_TYPE_MALWARE)).toBe(false);

    relationsRef = schemaRelationsRefDefinition.getRelationsRef(ENTITY_HASHED_OBSERVABLE_STIX_FILE);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_CONTAINS);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_HASHED_OBSERVABLE_ARTIFACT, ABSTRACT_STIX_CYBER_OBSERVABLE)).toBe(true);
    expect(relationRef.checker(ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_DIRECTORY)).toBe(true);
    relationsRef = schemaRelationsRefDefinition.getRelationsRef(ENTITY_HASHED_OBSERVABLE_STIX_FILE);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_PARENT_DIRECTORY);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_DIRECTORY)).toBe(true);
    expect(relationRef.checker(ENTITY_HASHED_OBSERVABLE_ARTIFACT, ABSTRACT_STIX_CYBER_OBSERVABLE)).toBe(false);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_CONTENT);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_HASHED_OBSERVABLE_ARTIFACT)).toBe(true);
    expect(relationRef.checker(ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_DIRECTORY)).toBe(false);

    relationsRef = schemaRelationsRefDefinition.getRelationsRef(ENTITY_IPV4_ADDR);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_RESOLVES_TO);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_IPV4_ADDR, ENTITY_MAC_ADDR)).toBe(true);
    expect(relationRef.checker(ENTITY_IPV4_ADDR, ENTITY_AUTONOMOUS_SYSTEM)).toBe(false);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_BELONGS_TO);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_IPV4_ADDR, ENTITY_AUTONOMOUS_SYSTEM)).toBe(true);
    expect(relationRef.checker(ENTITY_IPV4_ADDR, ENTITY_MAC_ADDR)).toBe(false);

    relationsRef = schemaRelationsRefDefinition.getRelationsRef(ENTITY_IPV6_ADDR);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_RESOLVES_TO);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_IPV6_ADDR, ENTITY_MAC_ADDR)).toBe(true);
    expect(relationRef.checker(ENTITY_IPV6_ADDR, ENTITY_AUTONOMOUS_SYSTEM)).toBe(false);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_BELONGS_TO);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_IPV6_ADDR, ENTITY_AUTONOMOUS_SYSTEM)).toBe(true);
    expect(relationRef.checker(ENTITY_IPV6_ADDR, ENTITY_MAC_ADDR)).toBe(false);

    relationsRef = schemaRelationsRefDefinition.getRelationsRef(ENTITY_NETWORK_TRAFFIC);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_SRC);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_NETWORK_TRAFFIC, ENTITY_DOMAIN_NAME)).toBe(true);
    expect(relationRef.checker(ENTITY_NETWORK_TRAFFIC, ENTITY_NETWORK_TRAFFIC)).toBe(false);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_DST);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_NETWORK_TRAFFIC, ENTITY_IPV4_ADDR)).toBe(true);
    expect(relationRef.checker(ENTITY_NETWORK_TRAFFIC, ENTITY_NETWORK_TRAFFIC)).toBe(false);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_SRC_PAYLOAD);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_NETWORK_TRAFFIC, ENTITY_HASHED_OBSERVABLE_ARTIFACT)).toBe(true);
    expect(relationRef.checker(ENTITY_NETWORK_TRAFFIC, ENTITY_IPV4_ADDR)).toBe(false);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_DST_PAYLOAD);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_NETWORK_TRAFFIC, ENTITY_HASHED_OBSERVABLE_ARTIFACT)).toBe(true);
    expect(relationRef.checker(ENTITY_NETWORK_TRAFFIC, ENTITY_IPV4_ADDR)).toBe(false);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_ENCAPSULATES);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_NETWORK_TRAFFIC, ENTITY_NETWORK_TRAFFIC)).toBe(true);
    expect(relationRef.checker(ENTITY_NETWORK_TRAFFIC, ENTITY_HASHED_OBSERVABLE_ARTIFACT)).toBe(false);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_ENCAPSULATED_BY);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_NETWORK_TRAFFIC, ENTITY_NETWORK_TRAFFIC)).toBe(true);
    expect(relationRef.checker(ENTITY_NETWORK_TRAFFIC, ENTITY_HASHED_OBSERVABLE_ARTIFACT)).toBe(false);

    relationsRef = schemaRelationsRefDefinition.getRelationsRef(ENTITY_PROCESS);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_OPENED_CONNECTION);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_PROCESS, ENTITY_NETWORK_TRAFFIC)).toBe(true);
    expect(relationRef.checker(ENTITY_PROCESS, ENTITY_HASHED_OBSERVABLE_ARTIFACT)).toBe(false);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_CREATOR_USER);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_PROCESS, ENTITY_USER_ACCOUNT)).toBe(true);
    expect(relationRef.checker(ENTITY_PROCESS, ENTITY_NETWORK_TRAFFIC)).toBe(false);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_IMAGE);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_PROCESS, ENTITY_HASHED_OBSERVABLE_STIX_FILE)).toBe(true);
    expect(relationRef.checker(ENTITY_PROCESS, ENTITY_NETWORK_TRAFFIC)).toBe(false);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_PARENT);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_PROCESS, ENTITY_PROCESS)).toBe(true);
    expect(relationRef.checker(ENTITY_PROCESS, ENTITY_NETWORK_TRAFFIC)).toBe(false);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_CHILD);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_PROCESS, ENTITY_PROCESS)).toBe(true);
    expect(relationRef.checker(ENTITY_PROCESS, ENTITY_NETWORK_TRAFFIC)).toBe(false);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_SERVICE_DLL);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_PROCESS, ENTITY_HASHED_OBSERVABLE_STIX_FILE)).toBe(true);
    expect(relationRef.checker(ENTITY_PROCESS, ENTITY_NETWORK_TRAFFIC)).toBe(false);

    relationsRef = schemaRelationsRefDefinition.getRelationsRef(ENTITY_WINDOWS_REGISTRY_KEY);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_VALUES);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_WINDOWS_REGISTRY_KEY, ENTITY_WINDOWS_REGISTRY_VALUE_TYPE)).toBe(true);
    expect(relationRef.checker(ENTITY_WINDOWS_REGISTRY_KEY, ENTITY_NETWORK_TRAFFIC)).toBe(false);
    [relationRef] = relationsRef.filter((rel) => rel.inputName === INPUT_CREATOR_USER);
    expect(relationRef).not.toBeNull();
    expect(relationRef.checker(ENTITY_WINDOWS_REGISTRY_KEY, ENTITY_USER_ACCOUNT)).toBe(true);
    expect(relationRef.checker(ENTITY_WINDOWS_REGISTRY_KEY, ENTITY_NETWORK_TRAFFIC)).toBe(false);
  });
});

describe('Testing stix ref extractor', () => {
  it('Stix ref extractor testing', () => {
    const json = {
      id: 'vulnerability--ae842ab6-eaba-5b26-9192-b24616c04cb1',
      spec_version: '2.1',
      type: 'vulnerability',
      extensions: {
        'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
          extension_type: 'property-extension',
          id: 'c096c1c9-94bd-4e07-8172-dff96e6a6cf0',
          type: 'Vulnerability',
          created_at: '2023-03-09T15:03:17.360Z',
          updated_at: '2023-03-09T15:03:17.360Z',
          stix_ids: ['vulnerability--d62a0bb6-a362-4abd-aeab-dc27d3561b48'],
          is_inferred: false,
          creator_ids: ['d49869a5-55f3-450b-ade2-996d036522a6']
        }
      },
      created: '2023-03-09T15:02:50.241Z',
      modified: '2023-03-09T15:02:50.241Z',
      revoked: false,
      confidence: 15,
      lang: 'en',
      object_marking_refs: ['marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da'],
      created_by_ref: 'identity--1f02efe5-c752-589e-85d4-a8da3898f690',
      external_references: [{ source_name: 'cve', external_id: 'CVE-2023-1292' }, {
        source_name: 'MISC',
        url: 'https://vuldb.com/?id.222646'
      }, { source_name: 'MISC', url: 'https://vuldb.com/?ctiid.222646' }, {
        source_name: 'MISC',
        url: 'https://github.com/Mart1nD0t/vul-test/blob/main/sts-3.md'
      }],
      name: 'CVE-2023-1292',
    };
    const refs = stixRefsExtractor(json, generateStandardId);
    expect(refs.includes('identity--1f02efe5-c752-589e-85d4-a8da3898f690')).toBe(true);
    expect(refs.includes('marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da')).toBe(true);
  });
});

describe('Testing relations mapping', () => {
  it('Relations types should map', () => {
    const mapping = schemaRelationsTypesMapping();
    let relations = mapping.find((m) => m.key === 'Infrastructure_IPv4-Addr').values;
    expect(relations.includes(RELATION_COMMUNICATES_WITH)).toBe(true); // Inheritance
    expect(relations.includes(RELATION_CONSISTS_OF)).toBe(true); // Merge

    relations = mapping.find((m) => m.key === 'Infrastructure_Software').values;
    expect(relations.filter((r) => r === RELATION_CONSISTS_OF).length).toBe(1); // Deduplication
  });
});
