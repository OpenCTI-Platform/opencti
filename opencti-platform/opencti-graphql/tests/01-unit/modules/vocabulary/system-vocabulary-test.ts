import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { getVocabulariesCategories, getVocabularyCategoryForField, isEntityFieldAnOpenVocabulary, openVocabularies } from '../../../../src/modules/vocabulary/vocabulary-utils';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL, ENTITY_TYPE_IDENTITY_SYSTEM } from '../../../../src/schema/stixDomainObject';
import { schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';

const SYSTEM_ASSET_FIELDS: Record<string, string> = {
  x_opencti_system_category: 'system_category_ov',
  x_opencti_system_subcategory: 'system_subcategory_ov',
  x_opencti_internet_facing: 'system_internet_facing_ov',
  x_opencti_criticality: 'system_criticality_ov',
  x_opencti_environment: 'system_environment_ov',
  x_opencti_platform: 'system_platform_ov',
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
    expect(closedOf('system_internet_facing_ov')).toBe(true);
    expect(closedOf('system_criticality_ov')).toBe(true);
    expect(closedOf('system_category_ov')).toBe(false);
    expect(closedOf('system_subcategory_ov')).toBe(false);
  });

  it('should ship the OpenAEV asset taxonomy values', () => {
    expect(openVocabularies.system_category_ov.map(({ key }) => key)).toEqual([
      'HOST', 'CONTAINER_WORKLOAD', 'CLOUD_RESOURCE', 'WEB_APPLICATION', 'NETWORK_DEVICE', 'MOBILE_DEVICE',
      'IOT_OT_DEVICE', 'IDENTITY', 'SAAS_APPLICATION', 'AI_TARGET', 'SECURITY_PLATFORM', 'GENERIC_ASSET',
    ]);
    expect(openVocabularies.system_criticality_ov.map(({ key }) => key)).toEqual(['VERY_HIGH', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']);
    expect(openVocabularies.system_internet_facing_ov.map(({ key }) => key)).toEqual(['yes', 'no', 'unknown']);
    expect(openVocabularies.system_subcategory_ov).toHaveLength(80);
    const subcategories = openVocabularies.system_subcategory_ov.map(({ key }) => key);
    expect(new Set(subcategories).size).toEqual(subcategories.length);
  });

  it('should give every option a one-line meaning', () => {
    Object.values(SYSTEM_ASSET_FIELDS).forEach((category) => {
      openVocabularies[category as keyof typeof openVocabularies].forEach(({ key, description }) => {
        expect(description, `${category}.${key}`).toBeTruthy();
      });
    });
  });

  it('should seed a colour on every value of the scales the overview colours', () => {
    ['system_category_ov', 'system_criticality_ov', 'system_environment_ov', 'system_internet_facing_ov'].forEach((category) => {
      openVocabularies[category as keyof typeof openVocabularies].forEach(({ key, color }) => {
        expect(color, `${category}.${key}`).toMatch(/^#[0-9a-f]{6}$/);
      });
    });
    // The scale reads from the most to the least severe: the top of each scale is never the neutral grey
    const colorOf = (category: keyof typeof openVocabularies, key: string) => openVocabularies[category].find((v) => v.key === key)?.color;
    expect(colorOf('system_criticality_ov', 'VERY_HIGH')).not.toEqual(colorOf('system_criticality_ov', 'UNKNOWN'));
    expect(colorOf('system_internet_facing_ov', 'yes')).not.toEqual(colorOf('system_internet_facing_ov', 'no'));
    // Each category is told apart by its colour
    const categoryColors = openVocabularies.system_category_ov.map(({ color }) => color);
    expect(new Set(categoryColors).size).toEqual(categoryColors.length);
  });

  it('should end every subcategory description with an existing category, which the form narrows on', () => {
    const categories = openVocabularies.system_category_ov.map(({ key }) => key);
    openVocabularies.system_subcategory_ov.forEach(({ key, description }) => {
      const category = description?.match(/\(category: ([A-Z_]+)\)$/)?.[1];
      expect(categories, key).toContain(category);
      // The meaning comes before the category, never the category alone
      expect(description?.replace(/\(category: [A-Z_]+\)$/, '').trim().length, key).toBeGreaterThan(5);
    });
  });
});

describe('System asset attributes', () => {
  it('should register the asset fields as optional filterable attributes of System', () => {
    [...Object.keys(SYSTEM_ASSET_FIELDS), 'x_opencti_owner'].forEach((field) => {
      const attribute = schemaAttributesDefinition.getAttribute(ENTITY_TYPE_IDENTITY_SYSTEM, field);
      expect(attribute).toMatchObject({ type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true, isFilterable: true });
    });
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_IDENTITY_INDIVIDUAL, 'x_opencti_system_category')).toBeUndefined();
  });
});
