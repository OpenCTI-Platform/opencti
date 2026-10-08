import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { curationAuthorityAttributes, normalizeCurationSettings } from '../../../../src/modules/curation/curation-settings';
import { DEFAULT_CURATED_ENTITY_TYPES } from '../../../../src/modules/curation/curation-defaults';
import { schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_INTRUSION_SET } from '../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_INDICATOR } from '../../../../src/modules/indicator/indicator-types';

describe('curated entity types', () => {
  it('keeps an empty list an administrator saved, and gives the defaults to a setting that never had one', () => {
    expect(normalizeCurationSettings({ curated_entity_types: [] }).curated_entity_types).toEqual([]);
    expect(normalizeCurationSettings({}).curated_entity_types).toEqual(DEFAULT_CURATED_ENTITY_TYPES);
    expect(normalizeCurationSettings(null).curated_entity_types).toEqual(DEFAULT_CURATED_ENTITY_TYPES);
    expect(normalizeCurationSettings({ curated_entity_types: null as never }).curated_entity_types).toEqual(DEFAULT_CURATED_ENTITY_TYPES);
    // Types the detectors cannot examine are dropped, even when nothing else is left.
    expect(normalizeCurationSettings({ curated_entity_types: [ENTITY_TYPE_CONTAINER_REPORT] }).curated_entity_types).toEqual([]);
    expect(normalizeCurationSettings({ curated_entity_types: [ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_CONTAINER_REPORT] }).curated_entity_types)
      .toEqual([ENTITY_TYPE_INTRUSION_SET]);
  });

  it('serves the settings the curatable types only: Indicator, no container', () => {
    const offered = curationAuthorityAttributes(schemaAttributesDefinition.registeredTypes).map((entry) => entry.entity_type);
    expect(offered).toContain(ENTITY_TYPE_INDICATOR);
    expect(offered).toContain(ENTITY_TYPE_INTRUSION_SET);
    expect(offered).not.toContain(ENTITY_TYPE_CONTAINER_REPORT);
    expect(offered).toEqual(expect.arrayContaining(DEFAULT_CURATED_ENTITY_TYPES));
  });
});
