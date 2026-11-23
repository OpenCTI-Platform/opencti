import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import {
  getVocabulariesCategories,
  getVocabularyCategoryForField,
  isEntityFieldAnOpenVocabulary,
  openVocabularies,
  seedVocabularyInput,
  systemSubcategoryParentFromDescription,
} from '../../../../src/modules/vocabulary/vocabulary-utils';
import { getVocabularyChildCategories } from '../../../../src/modules/vocabulary/vocabulary-domain';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL, ENTITY_TYPE_IDENTITY_SYSTEM } from '../../../../src/schema/stixDomainObject';
import { schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';
import { VocabularyCategory } from '../../../../src/generated/graphql';

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
      'IOT_OT_DEVICE', 'IDENTITY', 'SAAS_APPLICATION', 'AI_TARGET', 'SECURITY_PLATFORM', 'GENERIC_ASSET', 'SOURCE_CODE',
    ]);
    expect(openVocabularies.system_criticality_ov.map(({ key }) => key)).toEqual(['VERY_HIGH', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']);
    expect(openVocabularies.system_internet_facing_ov.map(({ key }) => key)).toEqual(['yes', 'no', 'unknown']);
    expect(openVocabularies.system_subcategory_ov).toHaveLength(85);
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
    const colorOf = (category: string, key: string) => openVocabularies[category as keyof typeof openVocabularies].find((v) => v.key === key)?.color;
    expect(colorOf('system_criticality_ov', 'VERY_HIGH')).not.toEqual(colorOf('system_criticality_ov', 'UNKNOWN'));
    expect(colorOf('system_internet_facing_ov', 'yes')).not.toEqual(colorOf('system_internet_facing_ov', 'no'));
    // Each category is told apart by its colour
    const categoryColors = openVocabularies.system_category_ov.map(({ color }) => color);
    expect(new Set(categoryColors).size).toEqual(categoryColors.length);
  });

  it('should seed the colour of an entry only when the entry carries one', () => {
    const critical = openVocabularies.system_criticality_ov.find(({ key }) => key === 'VERY_HIGH') ?? { key: 'VERY_HIGH' };
    expect(critical.color).toMatch(/^#[0-9a-f]{6}$/);
    expect(seedVocabularyInput(VocabularyCategory.SystemCriticalityOv, critical)).toMatchObject({
      name: 'VERY_HIGH', category: 'system_criticality_ov', color: critical.color, builtIn: false,
    });
    const plain = seedVocabularyInput(VocabularyCategory.AccountTypeOv, { key: 'ldap' });
    expect(plain).toEqual({ name: 'ldap', description: '', aliases: [], category: 'account_type_ov', order: undefined, builtIn: false });
    expect(plain).not.toHaveProperty('color');
  });

  it('should name an existing category in parent_name of every subcategory, which the form narrows on', () => {
    const categories = openVocabularies.system_category_ov.map(({ key }) => key);
    openVocabularies.system_subcategory_ov.forEach(({ key, description, parent_name }) => {
      expect(categories, key).toContain(parent_name);
      // The description is the meaning alone: the link never lives in a text the administrator edits (#20006)
      expect(description, key).not.toMatch(/\(category: /);
      expect(description?.trim().length, key).toBeGreaterThan(5);
    });
    // The five host subcategories of the issue keep their category
    const hosts = openVocabularies.system_subcategory_ov.filter(({ parent_name }) => parent_name === 'HOST').map(({ key }) => key);
    expect(hosts).toEqual(expect.arrayContaining(['SERVER', 'WORKSTATION', 'LAPTOP', 'VIRTUAL_MACHINE', 'HYPERVISOR']));
  });

  it('should ship the Source code category of the OpenAEV taxonomy with its five subcategories', () => {
    const sourceCode = openVocabularies.system_category_ov.find(({ key }) => key === 'SOURCE_CODE');
    expect(sourceCode).toMatchObject({ order: 13, description: 'Code repository, pipeline or package your teams build and ship.' });
    const codeSubcategories = openVocabularies.system_subcategory_ov.filter(({ parent_name }) => parent_name === 'SOURCE_CODE').map(({ key }) => key);
    expect(codeSubcategories).toEqual(['CODE_REPOSITORY', 'CI_CD_PIPELINE', 'PACKAGE_REGISTRY', 'SOFTWARE_PACKAGE', 'CODE_OTHER']);
  });

  it('should seed parent_name with the subcategory and leave it out elsewhere', () => {
    const server = openVocabularies.system_subcategory_ov.find(({ key }) => key === 'SERVER')!;
    expect(seedVocabularyInput(VocabularyCategory.SystemSubcategoryOv, server)).toMatchObject({ name: 'SERVER', parent_name: 'HOST' });
    expect(seedVocabularyInput(VocabularyCategory.SystemCategoryOv, openVocabularies.system_category_ov[0])).not.toHaveProperty('parent_name');
  });

  it('should carry a rename of a system category to the subcategories only', () => {
    expect(getVocabularyChildCategories(VocabularyCategory.SystemCategoryOv)).toEqual([VocabularyCategory.SystemSubcategoryOv]);
    expect(getVocabularyChildCategories(VocabularyCategory.SystemSubcategoryOv)).toEqual([]);
    expect(getVocabularyChildCategories(VocabularyCategory.AccountTypeOv)).toEqual([]);
  });

  it('should read the category of a subcategory written before parent_name from its description, for the migration', () => {
    // Every seeded subcategory as 7.261116.0 stored it: the description ends with its category
    openVocabularies.system_subcategory_ov.forEach(({ key, description, parent_name }) => {
      expect(systemSubcategoryParentFromDescription(`${description} (category: ${parent_name})`), key).toEqual({ parentName: parent_name, description });
    });
    // A custom category key may hold any character but a closing parenthesis
    expect(systemSubcategoryParentFromDescription('My probe (category: CUSTOM-HOST)')).toEqual({ parentName: 'CUSTOM-HOST', description: 'My probe' });
    // A custom subcategory that names no category keeps no parent: selectable under every category, as before
    expect(systemSubcategoryParentFromDescription('A custom subcategory')).toBeUndefined();
    expect(systemSubcategoryParentFromDescription('')).toBeUndefined();
    expect(systemSubcategoryParentFromDescription(null)).toBeUndefined();
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
