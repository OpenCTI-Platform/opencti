import { describe, expect, it } from 'vitest';
import { PLAYBOOK_CREATE_INDICATOR_COMPONENT } from '../../../../src/modules/playbook/components/create-indicator-component';
import { testBundleObject, testExecutor } from './playbook-components-test-utils';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import type { StixIndicator } from '../../../../src/modules/indicator/indicator-types';
import type { StixRelation } from '../../../../src/types/stix-2-1-sro';
import { RELATION_BASED_ON, RELATION_INDICATES } from '../../../../src/schema/stixCoreRelationship';
import type { StixId } from '../../../../src/types/stix-2-0-common';
import type { StixCyberObject } from '../../../../src/types/stix-2-1-common';

const OBSERVABLE_ID = 'domain-name--a1b2c3d4-0000-0000-0000-000000000001' as const;
const INTRUSION_SET_ID = 'intrusion-set--1ad04810-ab05-5873-96f5-a89d19607e1c' as const;
const REPORT_ID = 'report--b4754e7d-88b4-51d9-aac4-86edaad66c4d' as const;

const FAKE_PATTERN = "[domain-name:value = 'malicious.example.com']";

const domainObservable = (id: StixId = OBSERVABLE_ID) =>
  testBundleObject<StixCyberObject & { value: string }>({
    id,
    type: 'domain-name',
    value: 'malicious.example.com',
    octiExtension: {
      type: 'Domain-Name',
      id: '',
    },
  });

const reportObject = () =>
  testBundleObject({
    id: REPORT_ID,
    type: 'report',
    octiExtension: { type: 'Report', id: '' },
    object_refs: [OBSERVABLE_ID],
  });

describe('Create indicator component', () => {
  // ------------------------------------------------------------------
  // Basic indicator + based-on relationship creation
  // ------------------------------------------------------------------

  it('should create an indicator and a based-on relationship when main element is an observable', async () => {
    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: OBSERVABLE_ID,
        bundleObjects: [domainObservable()],
        configuration: { applyToElements: 'only-main', wrap_in_container: false, types: [] },
      }),
    );

    expect(result.output_port).toBe('out');

    const indicators = result.bundle.objects.filter((o) => o.type === 'indicator') as StixIndicator[];
    const relationships = result.bundle.objects.filter(
      (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_BASED_ON,
    ) as StixRelation[];

    expect(indicators).toHaveLength(1);
    expect(indicators[0].extensions[STIX_EXT_OCTI].type).toBe('Indicator');
    expect(indicators[0].pattern).toBe(FAKE_PATTERN);

    expect(relationships).toHaveLength(1);
    expect(relationships[0].source_ref).toBe(indicators[0].id);
    expect(relationships[0].target_ref).toBe(OBSERVABLE_ID);
  });

  // ------------------------------------------------------------------
  // Output port is 'unmodified' when main element is not an observable
  // ------------------------------------------------------------------

  it('should return unmodified port when main element is not a cyber observable', async () => {
    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: INTRUSION_SET_ID,
        bundleObjects: [
          testBundleObject({
            id: INTRUSION_SET_ID,
            type: 'intrusion-set',
            octiExtension: { type: 'Intrusion-Set', id: '' },
          }),
        ],
        configuration: { applyToElements: 'only-main', wrap_in_container: false, types: [] },
      }),
    );

    expect(result.output_port).toBe('unmodified');
    expect(result.bundle.objects.filter((o) => o.type === 'indicator')).toHaveLength(0);
  });

  // ------------------------------------------------------------------
  // Type filter — observable type NOT in the allowed list → skip
  // ------------------------------------------------------------------

  it('should not create an indicator when observable type is not in the types filter', async () => {
    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: OBSERVABLE_ID,
        bundleObjects: [domainObservable()],
        configuration: { applyToElements: 'only-main', wrap_in_container: false, types: ['IPv4-Addr'] },
      }),
    );

    expect(result.output_port).toBe('unmodified');
    expect(result.bundle.objects.filter((o) => o.type === 'indicator')).toHaveLength(0);
  });

  // ------------------------------------------------------------------
  // Type filter — observable type IS in the allowed list → create
  // ------------------------------------------------------------------

  it('should create an indicator when observable type matches the types filter', async () => {
    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: OBSERVABLE_ID,
        bundleObjects: [domainObservable()],
        configuration: { applyToElements: 'only-main', wrap_in_container: false, types: ['Domain-Name'] },
      }),
    );

    expect(result.output_port).toBe('out');
    expect(result.bundle.objects.filter((o) => o.type === 'indicator')).toHaveLength(1);
  });

  // ------------------------------------------------------------------
  // applyToElements: all-elements — creates indicators for every observable in the bundle
  // ------------------------------------------------------------------

  it('should create indicators for all observables in the bundle when applyToElements is all-elements', async () => {
    const OBSERVABLE_ID_2 = 'domain-name--a1b2c3d4-0000-0000-0000-000000000002' as StixId;

    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: OBSERVABLE_ID,
        bundleObjects: [domainObservable(OBSERVABLE_ID), domainObservable(OBSERVABLE_ID_2)],
        configuration: { applyToElements: 'all-elements', wrap_in_container: false, types: [] },
      }),
    );

    expect(result.output_port).toBe('out');

    const indicators = result.bundle.objects.filter((o) => o.type === 'indicator') as StixIndicator[];
    expect(indicators).toHaveLength(2);

    const basedOnRels = result.bundle.objects.filter(
      (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_BASED_ON,
    ) as StixRelation[];
    expect(basedOnRels).toHaveLength(2);
  });

  // ------------------------------------------------------------------
  // applyToElements: all-except-main — creates indicators for all except main
  // ------------------------------------------------------------------

  it('should create indicators for all observables except main when applyToElements is all-except-main', async () => {
    const OBSERVABLE_ID_2 = 'domain-name--a1b2c3d4-0000-0000-0000-000000000002' as StixId;

    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: OBSERVABLE_ID,
        bundleObjects: [domainObservable(OBSERVABLE_ID), domainObservable(OBSERVABLE_ID_2)],
        configuration: { applyToElements: 'all-except-main', wrap_in_container: false, types: [] },
      }),
    );

    expect(result.output_port).toBe('out');

    const indicators = result.bundle.objects.filter((o) => o.type === 'indicator') as StixIndicator[];
    expect(indicators).toHaveLength(1);

    const basedOnRels = result.bundle.objects.filter(
      (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_BASED_ON,
    ) as StixRelation[];
    expect(basedOnRels).toHaveLength(1);
    expect(basedOnRels[0].target_ref).toBe(OBSERVABLE_ID_2);
  });

  // ------------------------------------------------------------------
  // Wrap in container
  // ------------------------------------------------------------------

  it('should add indicator and based-on relationship to container object_refs when wrap_in_container=true', async () => {
    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: REPORT_ID,
        bundleObjects: [reportObject(), domainObservable()],
        configuration: { applyToElements: 'all-elements', wrap_in_container: true, types: [] },
      }),
    );

    expect(result.output_port).toBe('out');

    const indicators = result.bundle.objects.filter((o) => o.type === 'indicator') as StixIndicator[];
    expect(indicators).toHaveLength(1);

    const report = result.bundle.objects.find((o) => o.id === REPORT_ID) as any;
    expect(report.object_refs).toContain(indicators[0].id);

    const basedOnRels = result.bundle.objects.filter(
      (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_BASED_ON,
    ) as StixRelation[];
    expect(report.object_refs).toContain(basedOnRels[0].id);
  });

  // ------------------------------------------------------------------

  it('should create indicates relationships from related-to relationships in the bundle', async () => {
    const relatedToRelationship = {
      id: 'relationship--rel-001',
      type: 'relationship',
      relationship_type: 'related-to',
      source_ref: OBSERVABLE_ID,
      target_ref: INTRUSION_SET_ID,
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      extensions: {
        [STIX_EXT_OCTI]: {
          extension_type: 'property-extension',
          type: 'stix-core-relationship',
        },
      },
    };

    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: OBSERVABLE_ID,
        bundleObjects: [domainObservable(), relatedToRelationship as any],
        configuration: { applyToElements: 'only-main', wrap_in_container: false, types: [] },
      }),
    );

    expect(result.output_port).toBe('out');

    const indicators = result.bundle.objects.filter((o) => o.type === 'indicator') as StixIndicator[];
    expect(indicators).toHaveLength(1);

    const indicatesRels = result.bundle.objects.filter(
      (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_INDICATES,
    ) as StixRelation[];

    expect(indicatesRels).toHaveLength(1);
    expect(indicatesRels[0].source_ref).toBe(indicators[0].id);
    expect(indicatesRels[0].target_ref).toBe(INTRUSION_SET_ID);
  });
});
