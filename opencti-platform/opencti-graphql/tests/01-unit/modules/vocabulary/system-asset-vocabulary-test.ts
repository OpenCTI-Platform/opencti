import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { getVocabulariesCategories, getVocabularyCategoryForField, isEntityFieldAnOpenVocabulary, openVocabularies } from '../../../../src/modules/vocabulary/vocabulary-utils';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL, ENTITY_TYPE_IDENTITY_SYSTEM } from '../../../../src/schema/stixDomainObject';
import { schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';

const SYSTEM_ASSET_FIELDS: Record<string, string> = {
  x_opencti_asset_category: 'asset_category_ov',
  x_opencti_asset_subcategory: 'asset_subcategory_ov',
  x_opencti_internet_facing: 'asset_internet_facing_ov',
  x_opencti_criticality: 'asset_criticality_ov',
  x_opencti_environment: 'asset_environment_ov',
  x_opencti_platform: 'asset_platform_ov',
};

describe('System asset vocabularies', () => {
  it('should bind every asset vocabulary field to System only', () => {
    Object.entries(SYSTEM_ASSET_FIELDS).forEach(([field, category]) => {
      expect(isEntityFieldAnOpenVocabulary(field, ENTITY_TYPE_IDENTITY_SYSTEM)).toBe(true);
      expect(isEntityFieldAnOpenVocabulary(field, ENTITY_TYPE_IDENTITY_INDIVIDUAL)).toBe(false);
      expect(getVocabularyCategoryForField(field, ENTITY_TYPE_IDENTITY_SYSTEM).category).toEqual(category);
    });
  });

  it('should list the asset categories, internet facing and criticality as closed only where the scale is fixed', () => {
    const categories = getVocabulariesCategories();
    const closedOf = (key: string) => categories.find((c) => c.key === key)?.closed;
    expect(closedOf('asset_internet_facing_ov')).toBe(true);
    expect(closedOf('asset_criticality_ov')).toBe(true);
    expect(closedOf('asset_category_ov')).toBe(false);
    expect(closedOf('asset_subcategory_ov')).toBe(false);
  });

  it('should ship the OpenAEV asset taxonomy values', () => {
    expect(openVocabularies.asset_category_ov.map(({ key }) => key)).toEqual([
      'HOST', 'CONTAINER_WORKLOAD', 'CLOUD_RESOURCE', 'WEB_APPLICATION', 'NETWORK_DEVICE', 'MOBILE_DEVICE',
      'IOT_OT_DEVICE', 'IDENTITY', 'SAAS_APPLICATION', 'AI_TARGET', 'SECURITY_PLATFORM', 'GENERIC_ASSET',
    ]);
    expect(openVocabularies.asset_criticality_ov.map(({ key }) => key)).toEqual(['VERY_HIGH', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']);
    expect(openVocabularies.asset_internet_facing_ov.map(({ key }) => key)).toEqual(['yes', 'no', 'unknown']);
    expect(openVocabularies.asset_subcategory_ov).toHaveLength(80);
    const subcategories = openVocabularies.asset_subcategory_ov.map(({ key }) => key);
    expect(new Set(subcategories).size).toEqual(subcategories.length);
  });
});

describe('System asset attributes', () => {
  it('should register the asset fields as optional filterable attributes of System', () => {
    [...Object.keys(SYSTEM_ASSET_FIELDS), 'x_opencti_owner'].forEach((field) => {
      const attribute = schemaAttributesDefinition.getAttribute(ENTITY_TYPE_IDENTITY_SYSTEM, field);
      expect(attribute).toMatchObject({ type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true, isFilterable: true });
    });
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_IDENTITY_INDIVIDUAL, 'x_opencti_asset_category')).toBeUndefined();
  });
});
