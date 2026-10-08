import { readFileSync } from 'node:fs';
import path from 'node:path';
import Ajv from 'ajv';
import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import convertHuntToStix from '../../../../src/modules/hunt/hunt-converter';
import { HUNT_EXTENSION_SCHEMA_URL, huntExtensionDefinition, toPackHunt } from '../../../../src/modules/hunt/hunt-pack';
import type { StoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import { STIX_EXT_OCTI_HUNT } from '../../../../src/types/stix-2-1-extensions';

const REPOSITORY_FILES = 'https://raw.githubusercontent.com/OpenCTI-Platform/opencti/master/';
// The tests run from opencti-platform/opencti-graphql
const schemaFile = path.resolve(process.cwd(), '../..', HUNT_EXTENSION_SCHEMA_URL.slice(REPOSITORY_FILES.length));
const readSchema = () => JSON.parse(readFileSync(schemaFile, 'utf8'));

const HUNT_INSTANCE = {
  id: '5a0f2d8e-7c1b-4c55-9d0a-2f1e8b6c4d31',
  internal_id: '5a0f2d8e-7c1b-4c55-9d0a-2f1e8b6c4d31',
  standard_id: 'hunt--0b6f5c1e-3a2d-5e4f-8a9b-1c2d3e4f5a6b',
  entity_type: 'Hunt',
  name: 'Encoded PowerShell',
  description: 'Encoded PowerShell launched by office applications',
  hypothesis: 'An intrusion set runs encoded PowerShell from office documents on our endpoints',
  hunt_type: 'telemetry',
  hunt_status: 'active',
  hunt_source_kind: 'analyst',
  sigma_rule: 'title: Encoded PowerShell\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: -enc\n  condition: selection',
  native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr powershell -enc', pipeline: null }],
  hunt_ioc_values: [{ observable_type: 'IPv4-Addr', value: '198.51.100.7' }],
  hunt_scope: '{"mode":"and","filters":[],"filterGroups":[]}',
  hunt_schedule: '1d',
  trigger_filters: '',
  hunt_pir_activation: true,
  time_window_hours: 24,
  expected_observables: ['Process'],
  benign_patterns: ['Software deployment'],
  escalation_threshold: 10,
  escalate_manual_runs: false,
  hunt_max_results: 1000,
  confidence: 100,
  revoked: false,
  lang: 'en',
  created: '2026-10-01T08:00:00.000Z',
  modified: '2026-10-02T08:00:00.000Z',
  created_at: '2026-10-01T08:00:00.000Z',
  updated_at: '2026-10-02T08:00:00.000Z',
  huntTargets: [{ standard_id: 'intrusion-set--8c0e2bd4-3e2a-5c36-b1d6-9e0f1a2b3c4d' }],
  huntTechniques: [{ standard_id: 'attack-pattern--6c1e0b3f-2d4a-5b7c-8e9f-0a1b2c3d4e5f' }],
  huntSources: [{ standard_id: 'report--1d2e3f4a-5b6c-5d7e-8f9a-0b1c2d3e4f5a' }],
} as unknown as StoreEntityHunt;

// A hunt as written in a bundle
const exported = () => JSON.parse(JSON.stringify(convertHuntToStix(HUNT_INSTANCE)));

describe('JSON Schema of the hunt extension', () => {
  it('should be referenced by the hunt extension definition and kept in the repository at its address', () => {
    expect(huntExtensionDefinition().schema).toBe(HUNT_EXTENSION_SCHEMA_URL);
    expect(HUNT_EXTENSION_SCHEMA_URL.startsWith(REPOSITORY_FILES)).toBe(true);
    const schema = readSchema();
    expect(schema.$id).toBe(HUNT_EXTENSION_SCHEMA_URL);
    expect(schema.properties.extensions.required).toEqual([STIX_EXT_OCTI_HUNT]);
  });

  it('should describe the STIX form of a hunt, as exported and as distributed in a pack', () => {
    const validate = new Ajv({ allErrors: true }).compile(readSchema());
    const hunt = exported();
    expect(validate(hunt), JSON.stringify(validate.errors)).toBe(true);
    expect(validate(toPackHunt(hunt)), JSON.stringify(validate.errors)).toBe(true);
    // The extension, the type and the shape of the queries are part of the definition
    const { [STIX_EXT_OCTI_HUNT]: _hunt, ...otherExtensions } = hunt.extensions;
    expect(validate({ ...hunt, extensions: otherExtensions })).toBe(false);
    expect(validate({ ...hunt, hunt_type: 'unknown' })).toBe(false);
    expect(validate({ ...hunt, native_queries: [{ platform: 'splunk' }] })).toBe(false);
    // Like the platform: guardrails are whole numbers from 1, and the id names the type
    ['time_window_hours', 'escalation_threshold', 'hunt_max_results'].forEach((field) => {
      expect(validate({ ...hunt, [field]: 0 }), field).toBe(false);
      expect(validate({ ...hunt, [field]: 1.5 }), field).toBe(false);
    });
    expect(validate({ ...hunt, id: hunt.id.replace('hunt--', 'x-opencti-hunt--') })).toBe(false);
    expect(validate({ ...hunt, type: 'x-opencti-hunt', id: hunt.id.replace('hunt--', 'x-opencti-hunt--') })).toBe(true);
  });
});
