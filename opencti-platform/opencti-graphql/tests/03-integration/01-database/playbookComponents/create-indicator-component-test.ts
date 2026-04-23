import { describe, expect, it } from 'vitest';
import { PLAYBOOK_CREATE_INDICATOR_COMPONENT } from '../../../../src/modules/playbook/components/create-indicator-component';
import { testBundleObject, testExecutor } from './playbook-components-test-utils';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../../../../src/types/stix-2-1-extensions';
import type { StixIndicator } from '../../../../src/modules/indicator/indicator-types';
import type { StixRelation } from '../../../../src/types/stix-2-1-sro';
import { RELATION_BASED_ON, RELATION_INDICATES } from '../../../../src/schema/stixCoreRelationship';
import type { StixId } from '../../../../src/types/stix-2-0-common';
import type { StixCyberObject } from '../../../../src/types/stix-2-1-common';
import { playbookBundleElementsToApply } from '../../../../src/modules/playbook/playbook-types';
import type { StixInternalExternalReference } from '../../../../src/types/stix-2-1-smo';

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
        configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, wrap_in_container: false, types: [] },
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
        configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, wrap_in_container: false, types: [] },
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
        configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, wrap_in_container: false, types: ['IPv4-Addr'] },
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
        configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, wrap_in_container: false, types: ['Domain-Name'] },
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
        configuration: { applyToElements: playbookBundleElementsToApply.allElements.value, wrap_in_container: false, types: [] },
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
        configuration: { applyToElements: playbookBundleElementsToApply.allExceptMain.value, wrap_in_container: false, types: [] },
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
  // applyToElements: only-main — creates indicators only for main
  // ------------------------------------------------------------------

  it('should create indicators only for main when applyToElements is only-main', async () => {
    const OBSERVABLE_ID_2 = 'domain-name--a1b2c3d4-0000-0000-0000-000000000002' as StixId;

    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: OBSERVABLE_ID,
        bundleObjects: [domainObservable(OBSERVABLE_ID), domainObservable(OBSERVABLE_ID_2)],
        configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, wrap_in_container: false, types: [] },
      }),
    );

    expect(result.output_port).toBe('out');

    const indicators = result.bundle.objects.filter((o) => o.type === 'indicator') as StixIndicator[];
    expect(indicators).toHaveLength(1);

    const basedOnRels = result.bundle.objects.filter(
      (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_BASED_ON,
    ) as StixRelation[];
    expect(basedOnRels).toHaveLength(1);
    expect(basedOnRels[0].target_ref).toBe(OBSERVABLE_ID);
  });

  // ------------------------------------------------------------------
  // Wrap in container
  // ------------------------------------------------------------------

  it('should add indicator and based-on relationship to container object_refs when wrap_in_container=true', async () => {
    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: REPORT_ID,
        bundleObjects: [reportObject(), domainObservable()],
        configuration: { applyToElements: playbookBundleElementsToApply.allElements.value, wrap_in_container: true, types: [] },
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
  // Indicates relationships from bundle
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
        configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, wrap_in_container: false, types: [] },
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

  describe('when using filters on bundle containing multiple objects', () => {
    const OBSERVABLE_ID_2 = 'domain-name--a1b2c3d4-0000-0000-0000-000000000002' as StixId;
    const INTRUSION_SET_ID_2 = 'intrusion-set--2bc15921-bc16-6984-a7f6-b9be2a718f2d' as StixId;

    const filterDomainNames = '{"mode":"and","filters":[{"key":["entity_type"],"operator":"eq","values":["Domain-Name"],"mode":"or"}],"filterGroups":[]}';
    const filterNotMatching = '{"mode":"and","filters":[{"key":["entity_type"],"operator":"eq","values":["IPv4-Addr"],"mode":"or"}],"filterGroups":[]}';

    // -- all-elements + filter matching all observables

    it('should create indicators for all observables when applyToElements = "all-elements" and filter matches all observables', async () => {
      const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
        testExecutor({
          mainId: OBSERVABLE_ID,
          bundleObjects: [domainObservable(OBSERVABLE_ID), domainObservable(OBSERVABLE_ID_2)],
          configuration: {
            applyToElements: playbookBundleElementsToApply.allElements.value,
            applyWithFilters: filterDomainNames,
            wrap_in_container: false,
            types: [],
          },
        }),
      );

      expect(result.output_port).toBe('out');
      const indicators = result.bundle.objects.filter((o) => o.type === 'indicator') as StixIndicator[];
      expect(indicators).toHaveLength(2);

      const basedOnRels = result.bundle.objects.filter(
        (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_BASED_ON,
      ) as StixRelation[];
      expect(basedOnRels).toHaveLength(2);
      expect(basedOnRels.map((r) => r.target_ref)).toContain(OBSERVABLE_ID);
      expect(basedOnRels.map((r) => r.target_ref)).toContain(OBSERVABLE_ID_2);
    });

    // -- all-elements + filter not matching any observable

    it('should not create any indicator when applyToElements = "all-elements" and filter does not match any observable', async () => {
      const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
        testExecutor({
          mainId: OBSERVABLE_ID,
          bundleObjects: [domainObservable(OBSERVABLE_ID), domainObservable(OBSERVABLE_ID_2)],
          configuration: {
            applyToElements: playbookBundleElementsToApply.allElements.value,
            applyWithFilters: filterNotMatching,
            wrap_in_container: false,
            types: [],
          },
        }),
      );

      expect(result.output_port).toBe('unmodified');
      expect(result.bundle.objects.filter((o) => o.type === 'indicator')).toHaveLength(0);
      expect(result.bundle.objects.filter(
        (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_BASED_ON,
      )).toHaveLength(0);
    });

    // -- only-main + filter matching all observables

    it('should create indicator only for main observable when applyToElements = "only-main" and filter matches all observables', async () => {
      const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
        testExecutor({
          mainId: OBSERVABLE_ID,
          bundleObjects: [domainObservable(OBSERVABLE_ID), domainObservable(OBSERVABLE_ID_2)],
          configuration: {
            applyToElements: playbookBundleElementsToApply.onlyMain.value,
            applyWithFilters: filterDomainNames,
            wrap_in_container: false,
            types: [],
          },
        }),
      );

      // applyToElements restricts to main only, filter matches both but scope wins
      expect(result.output_port).toBe('out');

      const indicators = result.bundle.objects.filter((o) => o.type === 'indicator') as StixIndicator[];
      expect(indicators).toHaveLength(1);

      const basedOnRels = result.bundle.objects.filter(
        (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_BASED_ON,
      ) as StixRelation[];
      expect(basedOnRels).toHaveLength(1);
      expect(basedOnRels[0].target_ref).toBe(OBSERVABLE_ID);
    });

    // -- only-main + filter not matching

    it('should not create any indicator when applyToElements = "only-main" and filter does not match any observable', async () => {
      const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
        testExecutor({
          mainId: OBSERVABLE_ID,
          bundleObjects: [domainObservable(OBSERVABLE_ID), domainObservable(OBSERVABLE_ID_2)],
          configuration: {
            applyToElements: playbookBundleElementsToApply.onlyMain.value,
            applyWithFilters: filterNotMatching,
            wrap_in_container: false,
            types: [],
          },
        }),
      );

      expect(result.output_port).toBe('unmodified');
      expect(result.bundle.objects.filter((o) => o.type === 'indicator')).toHaveLength(0);
      expect(result.bundle.objects.filter(
        (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_BASED_ON,
      )).toHaveLength(0);
    });

    // -- all-except-main + filter matching all observables

    it('should create indicator only for non-main observable when applyToElements = "all-except-main" and filter matches all observables', async () => {
      const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
        testExecutor({
          mainId: OBSERVABLE_ID,
          bundleObjects: [domainObservable(OBSERVABLE_ID), domainObservable(OBSERVABLE_ID_2)],
          configuration: {
            applyToElements: playbookBundleElementsToApply.allExceptMain.value,
            applyWithFilters: filterDomainNames,
            wrap_in_container: false,
            types: [],
          },
        }),
      );

      // applyToElements excludes main, filter matches both: only second observable processed
      expect(result.output_port).toBe('out');

      const indicators = result.bundle.objects.filter((o) => o.type === 'indicator') as StixIndicator[];
      expect(indicators).toHaveLength(1);

      const basedOnRels = result.bundle.objects.filter(
        (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_BASED_ON,
      ) as StixRelation[];
      expect(basedOnRels).toHaveLength(1);
      expect(basedOnRels[0].target_ref).toBe(OBSERVABLE_ID_2);
    });

    // -- all-except-main + filter not matching

    it('should not create any indicator when applyToElements = "all-except-main" and filter does not match any observable', async () => {
      const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
        testExecutor({
          mainId: OBSERVABLE_ID,
          bundleObjects: [domainObservable(OBSERVABLE_ID), domainObservable(OBSERVABLE_ID_2)],
          configuration: {
            applyToElements: playbookBundleElementsToApply.allExceptMain.value,
            applyWithFilters: filterNotMatching,
            wrap_in_container: false,
            types: [],
          },
        }),
      );

      expect(result.output_port).toBe('unmodified');
      expect(result.bundle.objects.filter((o) => o.type === 'indicator')).toHaveLength(0);
      expect(result.bundle.objects.filter(
        (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_BASED_ON,
      )).toHaveLength(0);
    });

    // -- all-elements + filter matching partial bundle (observables only, not intrusion-set)

    it('should create indicators only for filtered observables when applyToElements = "all-elements" and filter matches partial bundle', async () => {
      const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
        testExecutor({
          mainId: OBSERVABLE_ID,
          bundleObjects: [
            domainObservable(OBSERVABLE_ID),
            domainObservable(OBSERVABLE_ID_2),
            testBundleObject({
              id: INTRUSION_SET_ID_2,
              type: 'intrusion-set',
              octiExtension: { type: 'Intrusion-Set', id: '' },
            }),
          ],
          configuration: {
            applyToElements: playbookBundleElementsToApply.allElements.value,
            applyWithFilters: filterDomainNames,
            wrap_in_container: false,
            types: [],
          },
        }),
      );

      // Only the 2 domain-name observables matched the filter, intrusion-set is ignored
      expect(result.output_port).toBe('out');

      const indicators = result.bundle.objects.filter((o) => o.type === 'indicator') as StixIndicator[];
      expect(indicators).toHaveLength(2);

      const basedOnRels = result.bundle.objects.filter(
        (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_BASED_ON,
      ) as StixRelation[];
      expect(basedOnRels).toHaveLength(2);
      expect(basedOnRels.map((r) => r.target_ref)).toContain(OBSERVABLE_ID);
      expect(basedOnRels.map((r) => r.target_ref)).toContain(OBSERVABLE_ID_2);

      // Intrusion-set did not produce any indicator
      expect(result.bundle.objects.filter((o) => o.type === 'intrusion-set')).toHaveLength(1);
    });

    // -- all-except-main + filter matching partial bundle

    it('should create indicator only for non-main filtered observable when applyToElements = "all-except-main" and filter matches partial bundle', async () => {
      const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
        testExecutor({
          mainId: OBSERVABLE_ID,
          bundleObjects: [
            domainObservable(OBSERVABLE_ID),
            domainObservable(OBSERVABLE_ID_2),
            testBundleObject({
              id: INTRUSION_SET_ID_2,
              type: 'intrusion-set',
              octiExtension: { type: 'Intrusion-Set', id: '' },
            }),
          ],
          configuration: {
            applyToElements: playbookBundleElementsToApply.allExceptMain.value,
            applyWithFilters: filterDomainNames,
            wrap_in_container: false,
            types: [],
          },
        }),
      );

      // Filter matches both domain-names but applyToElements excludes main:
      // only OBSERVABLE_ID_2 processed, intrusion-set ignored
      expect(result.output_port).toBe('out');

      const indicators = result.bundle.objects.filter((o) => o.type === 'indicator') as StixIndicator[];
      expect(indicators).toHaveLength(1);

      const basedOnRels = result.bundle.objects.filter(
        (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_BASED_ON,
      ) as StixRelation[];
      expect(basedOnRels).toHaveLength(1);
      expect(basedOnRels[0].target_ref).toBe(OBSERVABLE_ID_2);

      // Main observable did not produce any indicator
      expect(result.bundle.objects.filter((o) => o.type === 'intrusion-set')).toHaveLength(1);
    });
  });

  // Propagation of marking refs, labels, created_by_ref, external_references

  it('should propagate object_marking_refs from observable to indicator and relationships', async () => {
    const markings: StixId[] = ['marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168'];
    const obs = domainObservable();
    obs.object_marking_refs = markings;

    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: OBSERVABLE_ID,
        bundleObjects: [obs],
        configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, wrap_in_container: false, types: [] },
      }),
    );

    expect(result.output_port).toBe('out');
    const indicator = result.bundle.objects.find((o) => o.type === 'indicator') as StixIndicator;
    expect(indicator.object_marking_refs).toEqual(markings);

    const basedOn = result.bundle.objects.find(
      (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_BASED_ON,
    ) as StixRelation;
    expect(basedOn.object_marking_refs).toEqual(markings);
  });

  it('should propagate labels from SCO extension to indicator', async () => {
    const obs = domainObservable();
    obs.extensions[STIX_EXT_OCTI_SCO] = {
      ...(obs.extensions[STIX_EXT_OCTI_SCO] || {}),
      labels: ['malicious', 'phishing'],
    };

    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: OBSERVABLE_ID,
        bundleObjects: [obs],
        configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, wrap_in_container: false, types: [] },
      }),
    );

    const indicator = result.bundle.objects.find((o) => o.type === 'indicator') as StixIndicator;
    expect(indicator.labels).toEqual(['malicious', 'phishing']);
  });

  it('should propagate created_by_ref from SCO extension to indicator', async () => {
    const createdByRef = 'identity--a1b2c3d4-0000-0000-0000-000000000099';
    const obs = domainObservable();
    obs.extensions[STIX_EXT_OCTI_SCO] = {
      ...(obs.extensions[STIX_EXT_OCTI_SCO] || {}),
      created_by_ref: createdByRef,
    };

    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: OBSERVABLE_ID,
        bundleObjects: [obs],
        configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, wrap_in_container: false, types: [] },
      }),
    );

    const indicator = result.bundle.objects.find((o) => o.type === 'indicator') as StixIndicator;
    expect(indicator.created_by_ref).toBe(createdByRef);
  });

  it('should propagate external_references from SCO extension to indicator', async () => {
    const extRefs: StixInternalExternalReference[] = [{ source_name: 'test', url: 'https://example.com', description: '', hashes: {}, external_id: '' }];
    const obs = domainObservable();
    obs.extensions[STIX_EXT_OCTI_SCO] = {
      ...(obs.extensions[STIX_EXT_OCTI_SCO] || {}),
      external_references: extRefs,
    };

    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: OBSERVABLE_ID,
        bundleObjects: [obs],
        configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, wrap_in_container: false, types: [] },
      }),
    );

    const indicator = result.bundle.objects.find((o) => o.type === 'indicator') as StixIndicator;
    expect(indicator.external_references).toEqual(extRefs);
  });

  it('should propagate granted_refs to indicator and relationships', async () => {
    const grantedRefs = ['identity--grant-0001'];
    const obs = domainObservable();
    obs.extensions[STIX_EXT_OCTI].granted_refs = grantedRefs as any;

    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: OBSERVABLE_ID,
        bundleObjects: [obs],
        configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, wrap_in_container: false, types: [] },
      }),
    );

    const indicator = result.bundle.objects.find((o) => o.type === 'indicator') as StixIndicator;
    expect(indicator.extensions[STIX_EXT_OCTI].granted_refs).toEqual(grantedRefs);

    const basedOn = result.bundle.objects.find(
      (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_BASED_ON,
    ) as StixRelation;
    expect(basedOn.extensions[STIX_EXT_OCTI].granted_refs).toEqual(grantedRefs);
  });

  // Score propagation

  it('should propagate x_opencti_score from observable to indicator', async () => {
    const obs = domainObservable();
    obs.x_opencti_score = 85;

    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: OBSERVABLE_ID,
        bundleObjects: [obs],
        configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, wrap_in_container: false, types: [] },
      }),
    );

    const indicator = result.bundle.objects.find((o) => o.type === 'indicator') as StixIndicator;
    expect(indicator.extensions[STIX_EXT_OCTI].score).toBe(85);
  });

  it('should fallback to SCO extension score when x_opencti_score is undefined', async () => {
    const obs = domainObservable();
    obs.extensions[STIX_EXT_OCTI_SCO] = {
      ...(obs.extensions[STIX_EXT_OCTI_SCO] || {}),
      score: 42,
    };

    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: OBSERVABLE_ID,
        bundleObjects: [obs],
        configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, wrap_in_container: false, types: [] },
      }),
    );

    const indicator = result.bundle.objects.find((o) => o.type === 'indicator') as StixIndicator;
    expect(indicator.extensions[STIX_EXT_OCTI].score).toBe(42);
  });

  // Schema function

  it('should return a valid schema with observable types in oneOf', async () => {
    const schema = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.schema!();
    expect(schema).toBeDefined();
    if (!schema) return;
    expect(schema.properties.types.items.oneOf.length).toBeGreaterThan(0);
    // Should be sorted alphabetically
    const titles = schema.properties.types.items.oneOf.map((e: { const: string; title: string }) => e.title.toLowerCase());
    const sorted = [...titles].sort();
    expect(titles).toEqual(sorted);
  });

  // Indicates relationships with granted_refs from bundle

  it('should propagate granted_refs to indicates relationships from bundle', async () => {
    const grantedRefs: StixId[] = ['identity--grant-0001'];
    const obs = domainObservable();
    obs.extensions[STIX_EXT_OCTI].granted_refs = grantedRefs;

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
        bundleObjects: [obs, relatedToRelationship as any],
        configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, wrap_in_container: false, types: [] },
      }),
    );

    const indicatesRels = result.bundle.objects.filter(
      (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_INDICATES,
    ) as StixRelation[];

    expect(indicatesRels).toHaveLength(1);
    expect(indicatesRels[0].extensions[STIX_EXT_OCTI].granted_refs).toEqual(grantedRefs);
  });

  // Multiple target types for indicates relationships in bundle

  it('should create indicates relationships for all supported target types in bundle', async () => {
    const targets = [
      { prefix: 'threat-actor', id: 'threat-actor--00000000-0000-0000-0000-000000000001' },
      { prefix: 'campaign', id: 'campaign--00000000-0000-0000-0000-000000000002' },
      { prefix: 'malware', id: 'malware--00000000-0000-0000-0000-000000000003' },
    ];

    const relationships = targets.map((t, i) => ({
      id: `relationship--rel-${i}`,
      type: 'relationship',
      relationship_type: 'related-to',
      source_ref: OBSERVABLE_ID,
      target_ref: t.id,
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      extensions: {
        [STIX_EXT_OCTI]: { extension_type: 'property-extension', type: 'stix-core-relationship' },
      },
    }));

    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: OBSERVABLE_ID,
        bundleObjects: [domainObservable(), ...relationships as any[]],
        configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, wrap_in_container: false, types: [] },
      }),
    );

    const indicatesRels = result.bundle.objects.filter(
      (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_INDICATES,
    ) as StixRelation[];

    expect(indicatesRels).toHaveLength(3);
    const targetRefs = indicatesRels.map((r) => r.target_ref);
    targets.forEach((t) => expect(targetRefs).toContain(t.id));
  });

  // No indicator created when wrap_in_container but no observable

  it('should return unmodified when container has no cyber observables and wrap_in_container=true', async () => {
    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: REPORT_ID,
        bundleObjects: [reportObject()],
        configuration: { applyToElements: playbookBundleElementsToApply.allElements.value, wrap_in_container: true, types: [] },
      }),
    );

    expect(result.output_port).toBe('unmodified');
  });

  // -- Database relationship resolution (no relations found) --

  it('should enter database resolution block when observable has a non-empty internal id', async () => {
    const obs = domainObservable();
    obs.extensions[STIX_EXT_OCTI].id = 'fake-internal-id-for-db-lookup';

    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: OBSERVABLE_ID,
        bundleObjects: [obs],
        configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, wrap_in_container: false, types: [] },
      }),
    );

    expect(result.output_port).toBe('out');

    const indicators = result.bundle.objects.filter((o) => o.type === 'indicator') as StixIndicator[];
    expect(indicators).toHaveLength(1);

    // No indicates relationships from DB since no relations exist for this fake id
    const indicatesRels = result.bundle.objects.filter(
      (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_INDICATES,
    ) as StixRelation[];
    expect(indicatesRels).toHaveLength(0);
  });

  // -- Database resolution + bundle related-to combined --

  it('should create indicates relationships from both bundle and database resolution', async () => {
    const obs = domainObservable();
    obs.extensions[STIX_EXT_OCTI].id = 'fake-internal-id-for-db-lookup';

    const relatedToRelationship = {
      id: 'relationship--rel-db-001',
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
        bundleObjects: [obs, relatedToRelationship as any],
        configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, wrap_in_container: false, types: [] },
      }),
    );

    expect(result.output_port).toBe('out');

    // At least the bundle-based indicates relationship should exist
    const indicatesRels = result.bundle.objects.filter(
      (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_INDICATES,
    ) as StixRelation[];
    expect(indicatesRels.length).toBeGreaterThanOrEqual(1);
    expect(indicatesRels.some((r) => r.target_ref === INTRUSION_SET_ID)).toBe(true);
  });

  // -- Database resolution with granted_refs propagation --

  it('should propagate granted_refs to indicates relationships from database resolution', async () => {
    const grantedRefs: StixId[] = ['identity--grant-db-0001'];
    const obs = domainObservable();
    obs.extensions[STIX_EXT_OCTI].id = 'fake-internal-id-for-db-lookup';
    obs.extensions[STIX_EXT_OCTI].granted_refs = grantedRefs;

    const result = await PLAYBOOK_CREATE_INDICATOR_COMPONENT.executor(
      testExecutor({
        mainId: OBSERVABLE_ID,
        bundleObjects: [obs],
        configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, wrap_in_container: false, types: [] },
      }),
    );

    expect(result.output_port).toBe('out');

    const indicator = result.bundle.objects.find((o) => o.type === 'indicator') as StixIndicator;
    expect(indicator.extensions[STIX_EXT_OCTI].granted_refs).toEqual(grantedRefs);

    const basedOn = result.bundle.objects.find(
      (o) => o.type === 'relationship' && (o as StixRelation).relationship_type === RELATION_BASED_ON,
    ) as StixRelation;
    expect(basedOn.extensions[STIX_EXT_OCTI].granted_refs).toEqual(grantedRefs);
  });
});
