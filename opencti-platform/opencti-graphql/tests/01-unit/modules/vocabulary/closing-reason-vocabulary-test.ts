import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { getVocabulariesCategories, isEntityFieldAnOpenVocabulary, openVocabularies } from '../../../../src/modules/vocabulary/vocabulary-utils';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../../../../src/modules/case/case-incident/case-incident-types';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../../../../src/modules/draftWorkspace/draftWorkspace-types';
import { depsKeysRegister, schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';

describe('closing_reason_ov vocabulary', () => {
  it('should apply to every domain object type, including module ones', () => {
    const category = getVocabulariesCategories().find(({ key }) => key === 'closing_reason_ov');
    expect(category?.entity_types).toContain(ENTITY_TYPE_CONTAINER_REPORT);
    expect(category?.entity_types).toContain(ENTITY_TYPE_CONTAINER_CASE_INCIDENT);
    expect(category?.entity_types).not.toContain(ENTITY_TYPE_DRAFT_WORKSPACE);
  });

  it('should bind x_opencti_closing_reason as an open vocabulary field', () => {
    expect(isEntityFieldAnOpenVocabulary('x_opencti_closing_reason', ENTITY_TYPE_CONTAINER_CASE_INCIDENT)).toBe(true);
    expect(isEntityFieldAnOpenVocabulary('x_opencti_closing_reason', ENTITY_TYPE_DRAFT_WORKSPACE)).toBe(false);
  });

  it('should resolve x_opencti_closing_reason input dependencies for module domain objects', () => {
    const dependency = depsKeysRegister.get().find(({ src }) => src === 'x_opencti_closing_reason');
    expect(dependency?.types).toContain(ENTITY_TYPE_CONTAINER_CASE_INCIDENT);
  });

  it('should ship default values', () => {
    expect(openVocabularies.closing_reason_ov.map(({ key }) => key)).toEqual(['true-positive', 'false-positive', 'duplicate', 'indeterminate', 'other']);
  });
});

describe('x_opencti_closing_reason attribute', () => {
  it('should be a workflow-controlled vocabulary attribute of domain objects', () => {
    const attribute = schemaAttributesDefinition.getAttribute(ENTITY_TYPE_CONTAINER_CASE_INCIDENT, 'x_opencti_closing_reason');
    expect(attribute).toMatchObject({ format: 'vocabulary', vocabularyCategory: 'closing_reason_ov', editDefault: false, upsert: false, multiple: false });
  });

  it('should not exist on draft workspaces', () => {
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_DRAFT_WORKSPACE, 'x_opencti_closing_reason')).toBeUndefined();
  });
});
