import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { Client as ElkClient } from '@elastic/elasticsearch';
import {
  computeMappingFieldsLimit,
  countMappingFields,
  elCreateIndex,
  elCreateIndexWithMapping,
  elDeleteIndices,
  elIndexSetting,
  elPlatformMapping,
  elUpdateIndicesMappings,
  engine,
  ES_INDEX_PATTERN_SUFFIX,
  ES_MAPPING_FIELDS_HEADROOM,
  ES_MAX_MAPPINGS,
} from '../../../src/database/engine';
import { engineMappingGenerator } from '../../../src/database/engine-mapping-generator';
import { ES_INDEX_PREFIX } from '../../../src/database/utils';
import { logApp } from '../../../src/config/conf';

// A platform created years ago carries in its indices every attribute it ever mapped, because the engine never drops a
// mapped field. When a release adds attributes, the startup mapping update of such an index must fit its legacy fields,
// its schema and the new attributes, which can exceed the default fields limit. A fresh index only holds the current
// schema, so tests running on a fresh platform cannot reproduce it: this file builds a long-lived index on purpose.
const LIMIT_RAISE_WARNING = '[SEARCH] Index fields limit raised above the default to keep the headroom over the mapping';
// Fields added to the schema by the release the long-lived platform upgrades to.
const SCHEMA_GROWTH_FIELDS = 200;
// Fields still free under the default limit before the upgrade: fewer than the schema growth, so the new mapping
// cannot fit under the default limit.
const FREE_FIELDS_BEFORE_UPGRADE = 50;

const LONG_LIVED_ALIAS = `${ES_INDEX_PREFIX}_mapping_limit_long_lived`;
const LONG_LIVED_INDEX = `${LONG_LIVED_ALIAS}${ES_INDEX_PATTERN_SUFFIX}`;
const FRESH_ALIAS = `${ES_INDEX_PREFIX}_mapping_limit_fresh`;
const FRESH_INDEX = `${FRESH_ALIAS}${ES_INDEX_PATTERN_SUFFIX}`;

// Mapping of the long-lived index before the upgrade: the current schema without the attributes of the release
// (taken from the end of the sorted attribute list), plus the legacy attributes the schema removed since.
const buildLongLivedMapping = () => {
  const generated = engineMappingGenerator(engine);
  const growthKeys: string[] = [];
  let growthFields = 0;
  const keysFromTheEnd = Object.keys(generated).sort().reverse();
  for (let i = 0; i < keysFromTheEnd.length && growthFields < SCHEMA_GROWTH_FIELDS; i += 1) {
    const key = keysFromTheEnd[i];
    growthKeys.push(key);
    growthFields += countMappingFields({ [key]: generated[key] });
  }
  const previousSchema = Object.fromEntries(Object.entries(generated).filter(([key]) => !growthKeys.includes(key)));
  const previousSchemaFields = countMappingFields(previousSchema);
  const legacyFieldsCount = ES_MAX_MAPPINGS - FREE_FIELDS_BEFORE_UPGRADE - previousSchemaFields;
  if (legacyFieldsCount < 0) {
    // The schema grew past what the fixture can model: say so instead of failing on a negative array length.
    throw new Error(`The generated schema already uses ${previousSchemaFields} fields, more than the ${ES_MAX_MAPPINGS - FREE_FIELDS_BEFORE_UPGRADE} `
      + 'the long-lived fixture can hold before the upgrade: raise ES_MAX_MAPPINGS or lower FREE_FIELDS_BEFORE_UPGRADE in this test');
  }
  const legacy = Object.fromEntries(Array.from({ length: legacyFieldsCount }, (_, i) => [`legacy_attribute_${i}`, { type: 'keyword' }]));
  return { mapping: { ...legacy, ...previousSchema }, generatedKeys: Object.keys(generated), growthKeys, growthFields, legacyKeys: Object.keys(legacy) };
};

const indexFieldsLimit = async (index: string): Promise<number> => {
  const { settings } = await elIndexSetting(index);
  return Number(settings.index.mapping?.total_fields?.limit);
};

// `engine` is an ElkClient | OpenClient union: TypeScript refuses a single call on the union because the two clients'
// method signatures are not compatible, hence the narrowing branch (the same pattern as the engine module itself).
const putIndexFieldsLimit = async (index: string, limit: number) => {
  const args = { index, body: { index: { mapping: { total_fields: { limit } } } } };
  if (engine instanceof ElkClient) {
    await engine.indices.putSettings(args);
  } else {
    await engine.indices.putSettings(args);
  }
};

const deleteIndexTemplate = async (name: string) => {
  if (engine instanceof ElkClient) {
    await engine.indices.deleteIndexTemplate({ name }, { ignore: [404] });
  } else {
    await engine.indices.deleteIndexTemplate({ name }, { ignore: [404] });
  }
};

// Restricted to the given indices: other test files leave indices under the test prefix that were not created through
// the platform template. The platform error only says "Updating index mapping fail": surface the index and the engine
// reason it carries.
const updateIndicesMappings = async (indexNames: string[]) => {
  try {
    await elUpdateIndicesMappings(indexNames);
  } catch (e: any) {
    const { index, cause } = e.extensions?.data ?? {};
    throw new Error(`${e.message} on index ${index}: ${JSON.stringify(cause?.meta?.body?.error ?? cause?.message)}`, { cause: e });
  }
};

const removeFixtures = async () => {
  await elDeleteIndices([LONG_LIVED_INDEX, FRESH_INDEX]);
  await deleteIndexTemplate(LONG_LIVED_ALIAS);
  await deleteIndexTemplate(FRESH_ALIAS);
};

describe('Search engine fields limit on long-lived indices', () => {
  let longLived: ReturnType<typeof buildLongLivedMapping>;

  beforeAll(async () => {
    longLived = buildLongLivedMapping();
    await removeFixtures();
    // Created through the platform template path, so the index gets the platform settings, normalizer and alias.
    await elCreateIndexWithMapping(LONG_LIVED_ALIAS, longLived.mapping);
    // Before the fields limit was sized from the mapping, every index kept the default limit whatever it held.
    await putIndexFieldsLimit(LONG_LIVED_INDEX, ES_MAX_MAPPINGS);
    await elCreateIndex(FRESH_ALIAS);
  });

  afterAll(async () => {
    await removeFixtures();
  });

  it('should hold a long-lived index fixture that cannot take the new schema under the default limit', async () => {
    const mapping = await elPlatformMapping(LONG_LIVED_INDEX);
    const fields = countMappingFields(mapping);
    expect(await indexFieldsLimit(LONG_LIVED_INDEX)).toBe(ES_MAX_MAPPINGS);
    expect(longLived.legacyKeys.length).toBeGreaterThan(0);
    expect(longLived.legacyKeys.filter((key) => mapping[key] === undefined)).toEqual([]);
    expect(longLived.growthKeys.filter((key) => mapping[key] !== undefined)).toEqual([]);
    expect(fields).toBeLessThanOrEqual(ES_MAX_MAPPINGS);
    expect(fields + longLived.growthFields).toBeGreaterThan(ES_MAX_MAPPINGS);
  });

  it('should raise the fields limit of a long-lived index instead of failing the startup mapping update', async () => {
    const warnSpy = vi.spyOn(logApp, 'warn');
    try {
      await updateIndicesMappings([LONG_LIVED_INDEX]);
      const mapping = await elPlatformMapping(LONG_LIVED_INDEX);
      const fields = countMappingFields(mapping);
      // The index now holds every attribute of the current schema and still keeps its legacy fields.
      expect(longLived.generatedKeys.filter((key) => mapping[key] === undefined)).toEqual([]);
      expect(longLived.legacyKeys.filter((key) => mapping[key] === undefined)).toEqual([]);
      expect(fields).toBeGreaterThan(ES_MAX_MAPPINGS);
      const limit = await indexFieldsLimit(LONG_LIVED_INDEX);
      expect(limit).toBe(computeMappingFieldsLimit(mapping));
      expect(limit).toBe(fields + ES_MAPPING_FIELDS_HEADROOM);
      expect(warnSpy).toHaveBeenCalledWith(LIMIT_RAISE_WARNING, { index: LONG_LIVED_INDEX, fields, limit, default_limit: ES_MAX_MAPPINGS });
    } finally {
      warnSpy.mockRestore();
    }
  });

  it('should keep the default fields limit on a fresh index', async () => {
    expect(await indexFieldsLimit(FRESH_INDEX)).toBe(ES_MAX_MAPPINGS);
    const warnSpy = vi.spyOn(logApp, 'warn');
    try {
      await updateIndicesMappings([FRESH_INDEX]);
      const mapping = await elPlatformMapping(FRESH_INDEX);
      expect(computeMappingFieldsLimit(mapping)).toBe(ES_MAX_MAPPINGS);
      expect(await indexFieldsLimit(FRESH_INDEX)).toBe(ES_MAX_MAPPINGS);
      expect(warnSpy).not.toHaveBeenCalledWith(LIMIT_RAISE_WARNING, expect.objectContaining({ index: FRESH_INDEX }));
    } finally {
      warnSpy.mockRestore();
    }
  });
});
