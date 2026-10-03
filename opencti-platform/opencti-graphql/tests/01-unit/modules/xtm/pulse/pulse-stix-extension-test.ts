import { describe, expect, it } from 'vitest';
import { buildOCTIExtensions } from '../../../../../src/database/stix-2-1-converter';
import { buildPulseDocument, buildPulsePreviewDocument, combinePulseLookups } from '../../../../../src/modules/xtm/pulse/pulse-information';
import { PULSE_ENTITY_ATTRIBUTES, PULSE_SCOPE_ENTITY_TYPES } from '../../../../../src/modules/xtm/pulse/pulse-types';
import { INTERNAL_ATTRIBUTES } from '../../../../../src/domain/attribute-utils';
import { schemaAttributesDefinition } from '../../../../../src/schema/schema-attributes';
import { validateUpdatableAttribute } from '../../../../../src/schema/schema-validator';
import { PulsePrevalence, PulseTrend } from '../../../../../src/generated/graphql';
import { ENTITY_TYPE_INDICATOR } from '../../../../../src/modules/indicator/indicator-types';
import type { StoreObject } from '../../../../../src/types/store';
import '../../../../../src/modules/index';

const indicator = (pulse: Record<string, unknown>) => ({
  _index: 'opencti_stix_domain_objects-000001',
  internal_id: 'f13cbb68-7a0c-4d2f-9f3e-2b4a1f0c8a11',
  standard_id: 'indicator--5b0e1d6e-6a24-5a5a-9d2a-1f0b8c3e4d21',
  entity_type: ENTITY_TYPE_INDICATOR,
  created_at: '2026-09-30T10:00:00.000Z',
  updated_at: '2026-09-30T10:00:00.000Z',
  ...pulse,
}) as unknown as StoreObject;

describe('Threat Pulse fields in the OpenCTI STIX extension', () => {
  it('should carry the community signal under stable names', () => {
    const information = combinePulseLookups([{
      hash: 'a',
      published: true,
      prevalence_bucket: PulsePrevalence.Common,
      platforms_bucket: '25-49',
      first_seen_network: '2026-08-14',
      last_seen_network: '2026-10-02',
      trend: PulseTrend.Rising,
      trend_series: [1, 2, 8],
      sector_trend: PulseTrend.Rising,
      sector_platforms_bucket: '5-9',
    }]);
    const document = buildPulseDocument(['00112233445566778899aabbccddeeff'], information, new Date('2026-10-03T00:00:00.000Z'));
    const extension = buildOCTIExtensions(indicator(document));
    expect(extension.pulse_prevalence).toBe('common');
    expect(extension.pulse_trend).toBe('rising');
    expect(extension.pulse_sector_trend).toBe('rising');
    expect(extension.pulse_first_seen_network).toBe('2026-08-14T00:00:00.000Z');
    expect(extension.pulse_community_uniqueness).toBe(information.communityUniqueness);
    expect(extension).not.toHaveProperty('pulse_preview');
  });

  it('should mark the coarse preview signal for stream consumers', () => {
    const document = buildPulsePreviewDocument(['00112233445566778899aabbccddeeff'], { prevalence: PulsePrevalence.Widespread, trend: PulseTrend.Rising }, new Date());
    const extension = buildOCTIExtensions(indicator(document)) as unknown as Record<string, unknown>;
    expect(extension).toMatchObject({ pulse_prevalence: 'widespread', pulse_trend: 'rising', pulse_preview: true });
    ['pulse_sector_trend', 'pulse_first_seen_network', 'pulse_community_uniqueness', 'pulse_keys', 'pulse_information']
      .forEach((name) => expect(extension).not.toHaveProperty(name));
  });

  it('should never expose the local keys or the stored network details', () => {
    const document = buildPulseDocument(['00112233445566778899aabbccddeeff'], combinePulseLookups([]), new Date());
    const extension = buildOCTIExtensions(indicator(document)) as unknown as Record<string, unknown>;
    expect(extension).not.toHaveProperty('pulse_keys');
    expect(extension).not.toHaveProperty('pulse_information');
    expect(JSON.stringify(extension)).not.toContain('00112233445566778899aabbccddeeff');
  });

  it('should leave the extension unchanged for objects without Threat Pulse information', () => {
    const extension = buildOCTIExtensions(indicator({})) as unknown as Record<string, unknown>;
    expect(Object.keys(extension).filter((key) => key.startsWith('pulse_'))).toEqual([]);
  });
});

describe('Threat Pulse attributes protection', () => {
  it('should refuse any update of the network data through the API', () => {
    PULSE_SCOPE_ENTITY_TYPES.forEach((entityType) => {
      const input = Object.fromEntries(PULSE_ENTITY_ATTRIBUTES.map((name) => [name, 'value']));
      expect(validateUpdatableAttribute(entityType, input).sort()).toEqual([...PULSE_ENTITY_ATTRIBUTES].sort());
    });
  });

  it('should keep the network data out of imports and form intakes', () => {
    PULSE_ENTITY_ATTRIBUTES.forEach((name) => expect(INTERNAL_ATTRIBUTES).toContain(name));
  });

  it('should never upsert the network data from an integration', () => {
    PULSE_SCOPE_ENTITY_TYPES.forEach((entityType) => {
      PULSE_ENTITY_ATTRIBUTES.forEach((name) => {
        expect(schemaAttributesDefinition.getAttribute(entityType, name)?.upsert).toBe(false);
      });
    });
  });
});
