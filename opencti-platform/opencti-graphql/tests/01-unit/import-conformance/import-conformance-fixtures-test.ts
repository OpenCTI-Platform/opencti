/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { convertStoreToStix_2_1 } from '../../../src/database/stix-2-1-converter';
import { convertStoreToStix_2_0 } from '../../../src/database/stix-2-0-converter';
import type { StoreCommon } from '../../../src/types/store';
import { bundleOf, expectNoOrphanFixtures, type GeneratedFixture, writeOrCheckFixture } from './import-conformance-utils';

// Import conformance fixtures generated from the store instances of the converter tests: each
// instance gives the STIX the platform itself sends to an importer, in the 2.1 form (OpenCTI
// extensions) and in the 2.0 form (top-level x_opencti_* fields, the form connectors use).
// This test keeps those fixtures equal to the converters' output (see import-conformance-utils).
const CONVERTER_FIXTURES = '../database/stix-2-0-converter-fixtures';
const GROUPS: Record<string, string> = { SDOs: 'sdo', SCOs: 'sco', SMOs: 'smo', SROs: 'sro' };

// Types the converter fixtures do not cover. They exist in the 2.1 form only (new-sdo extension,
// no 2.0 converter): that is the only form the platform or OpenAEV send them in.
const BASE_INSTANCE = {
  created_at: '2025-01-01T00:00:00.000Z',
  updated_at: '2025-01-02T00:00:00.000Z',
  x_opencti_stix_ids: [],
  base_type: 'ENTITY',
  createdBy: { standard_id: 'identity--c801c762-92e8-58b6-9bcb-6fa805f902cb' },
  objectMarking: [{ standard_id: 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1' }],
};
const EXTRA_INSTANCES: Record<string, Record<string, unknown>> = {
  LANGUAGE_INSTANCE: {
    ...BASE_INSTANCE,
    id: '10000000-0000-4000-8000-000000000901',
    internal_id: '10000000-0000-4000-8000-000000000901',
    standard_id: 'language--20000000-0000-4000-8000-000000000901',
    entity_type: 'Language',
    parent_types: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
    name: 'Portuguese',
    aliases: ['pt'],
  },
  VOCABULARY_INSTANCE: {
    ...BASE_INSTANCE,
    id: '10000000-0000-4000-8000-000000000902',
    internal_id: '10000000-0000-4000-8000-000000000902',
    standard_id: 'vocabulary--20000000-0000-4000-8000-000000000902',
    entity_type: 'Vocabulary',
    parent_types: ['Basic-Object', 'Stix-Object', 'Stix-Meta-Object'],
    name: 'dropper',
    description: 'A dropper malware',
    category: 'malware_type_ov',
    aliases: ['loader'],
  },
  SECURITY_COVERAGE_INSTANCE: {
    ...BASE_INSTANCE,
    id: '10000000-0000-4000-8000-000000000903',
    internal_id: '10000000-0000-4000-8000-000000000903',
    standard_id: 'security-coverage--20000000-0000-4000-8000-000000000903',
    entity_type: 'Security-Coverage',
    parent_types: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
    name: 'Coverage of APT28',
    description: 'Scenario coverage',
    periodicity: 'P1W',
    type_affinity: 'ENDPOINT',
    platforms_affinity: ['windows'],
    duration: 'PT1H',
    objectCovered: { standard_id: 'intrusion-set--20000000-0000-4000-8000-000000000904' },
    resultOf: [{ standard_id: 'security-coverage-result--20000000-0000-4000-8000-000000000905' }],
  },
  // The same coverage without its results: the form pycti can import (see KNOWN_FAILURES)
  SECURITY_COVERAGE_WITHOUT_RESULT_INSTANCE: {
    ...BASE_INSTANCE,
    id: '10000000-0000-4000-8000-000000000903',
    internal_id: '10000000-0000-4000-8000-000000000903',
    standard_id: 'security-coverage--20000000-0000-4000-8000-000000000903',
    entity_type: 'Security-Coverage',
    parent_types: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
    name: 'Coverage of APT28',
    description: 'Scenario coverage',
    periodicity: 'P1W',
    type_affinity: 'ENDPOINT',
    platforms_affinity: ['windows'],
    duration: 'PT1H',
    objectCovered: { standard_id: 'intrusion-set--20000000-0000-4000-8000-000000000904' },
  },
  SECURITY_COVERAGE_RESULT_INSTANCE: {
    ...BASE_INSTANCE,
    id: '10000000-0000-4000-8000-000000000905',
    internal_id: '10000000-0000-4000-8000-000000000905',
    standard_id: 'security-coverage-result--20000000-0000-4000-8000-000000000905',
    entity_type: 'Security-Coverage-Result',
    parent_types: ['Basic-Object', 'Internal-Object'],
    name: 'security coverage result',
    external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a131',
    coverage_last_result: '2025-02-01T00:00:00.000Z',
    coverage_valid_from: '2025-03-01T00:00:00.000Z',
    coverage_valid_to: '2025-04-01T00:00:00.000Z',
    coverage_information: [{ coverage_name: 'vulnerability', coverage_score: 40 }],
    resultOf: { standard_id: 'security-coverage--20000000-0000-4000-8000-000000000903' },
  },
};

const modules = import.meta.glob('../database/stix-2-0-converter-fixtures/**/*.ts', { eager: true }) as Record<string, Record<string, unknown>>;

const variantName = (exportName: string) => exportName.replace(/_?INSTANCE_?/, '').toLowerCase().replaceAll('_', '-');

// Fixtures pycti cannot transform: declared, with the reason in their SOURCE
const KNOWN_FAILURES: Record<string, string> = {
  SECURITY_COVERAGE_INSTANCE: 'Known pycti defect: the splitter reads result_of_ref (a list) as one reference, the bundle fails.',
};

const extraFixtures = (): GeneratedFixture[] => Object.entries(EXTRA_INSTANCES).map(([name, instance]) => {
  const stix = convertStoreToStix_2_1(instance as unknown as StoreCommon);
  const knownFailure = KNOWN_FAILURES[name];
  return {
    path: `${stix.type === 'vocabulary' ? 'smo' : 'sdo'}/${stix.type}/converter-${variantName(name)}.ext`,
    source: `C': convertStoreToStix_2_1(${name}), opencti-graphql tests/01-unit/import-conformance/import-conformance-fixtures-test.ts${knownFailure ? `\n${knownFailure}` : ''}`,
    input: bundleOf(stix),
    ...(knownFailure ? { call: { expect_errors: true } } : {}),
  };
});

const generatedFixtures = (): GeneratedFixture[] => [...extraFixtures(), ...Object.entries(modules).flatMap(([file, exports]) => {
  const group = GROUPS[file.slice(CONVERTER_FIXTURES.length + 1).split('/')[0]];
  return Object.entries(exports)
    .filter(([name]) => name.includes('INSTANCE'))
    .flatMap(([name, instance]) => {
      const forms = [
        { form: 'ext', stix: convertStoreToStix_2_1(instance as StoreCommon) },
        { form: 'legacy', stix: convertStoreToStix_2_0(instance as StoreCommon) },
      ];
      return forms.map(({ form, stix }) => ({
        path: `${group}/${stix.type}/converter-${variantName(name)}.${form}`,
        source: `C': ${form === 'ext' ? 'convertStoreToStix_2_1' : 'convertStoreToStix_2_0'}(${name}), opencti-graphql tests/01-unit/database/${file.slice(3)}`,
        input: bundleOf(stix),
      }));
    });
})];

describe('Import conformance fixtures from the converters', () => {
  const fixtures = generatedFixtures();
  it('should cover every converter fixture instance', () => {
    expect(fixtures.length).toBeGreaterThan(0);
  });
  it.each(fixtures.map((fixture) => [fixture.path, fixture] as const))('%s', (_, fixture) => {
    writeOrCheckFixture(fixture);
  });
  it('should leave no fixture it does not generate anymore', () => {
    expectNoOrphanFixtures("C':", fixtures);
  });
});
