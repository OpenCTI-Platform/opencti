import { describe, expect, it, vi, afterEach, beforeEach } from 'vitest';
import type { StixBundle, StixObject, StixOpenctiExtension } from '../../../../src/types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import { PLAYBOOK_REDUCING_COMPONENT } from '../../../../src/modules/playbook/playbook-components';
import * as access from '../../../../src/utils/access';
import * as filterUtils from '../../../../src/utils/filtering/filtering-stix/stix-filtering';

const REPORT_ID = 'report--5f78a68b-2c4d-5e6f-beaa-7b987b0e7165';
const CAMPAIGN_ID = 'campaign--fdcacc8e-de4d-5a13-8886-401d363664fd';
const MALWARE_ID = 'malware--a1b2c3d4-e5f6-7890-abcd-ef1234567890';

const createBundle = (...objects: StixObject[]): StixBundle => ({
  id: 'bundle--00000000-0000-0000-0000-000000000001',
  spec_version: '2.1',
  type: 'bundle',
  objects,
} as StixBundle);

const createObject = (id: string, type: string): StixObject => ({
  id,
  spec_version: '2.1',
  type,
  extensions: {
    [STIX_EXT_OCTI]: { extension_type: 'property-extension', id: `ext-${id}`, type } as StixOpenctiExtension,
  },
} as StixObject);

const callExecutor = (bundle: StixBundle, filters: object = {}) =>
  PLAYBOOK_REDUCING_COMPONENT.executor({
    dataInstanceId: REPORT_ID,
    eventId: '',
    executionId: '',
    playbookId: '',
    previousPlaybookNodeId: undefined,
    previousStepBundle: null as StixBundle | null,
    bundle,
    playbookNode: {
      id: 'playbook-node-reduce',
      name: 'reduce-node',
      component_id: 'PLAYBOOK_REDUCING_COMPONENT',
      configuration: { filters: JSON.stringify(filters) },
    },
  });

describe('PLAYBOOK_REDUCING_COMPONENT', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(access, 'executionContext').mockReturnValue({} as any);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return base element (Report) + matched element (Campaign) when filter matches Campaign', async () => {
    const report = createObject(REPORT_ID, 'report');
    const campaign = createObject(CAMPAIGN_ID, 'campaign');
    const bundle = createBundle(report, campaign);

    vi.spyOn(filterUtils, 'isStixMatchFilterGroup')
      .mockResolvedValueOnce(false) // report does not match filter
      .mockResolvedValueOnce(true); // campaign matches filter

    const result = await callExecutor(bundle);

    expect(result.output_port).toBe('out');
    expect(result.bundle.objects).toHaveLength(2);
    expect(result.bundle.objects.find((o) => o.id === REPORT_ID)).toBeDefined(); // base element always included
    expect(result.bundle.objects.find((o) => o.id === CAMPAIGN_ID)).toBeDefined(); // matched element included
  });

  it('should return base element (Report) + matched element (Malware) when filter matches Malware', async () => {
    const report = createObject(REPORT_ID, 'report');
    const campaign = createObject(CAMPAIGN_ID, 'campaign');
    const malware = createObject(MALWARE_ID, 'malware');
    const bundle = createBundle(report, campaign, malware);

    vi.spyOn(filterUtils, 'isStixMatchFilterGroup')
      .mockResolvedValueOnce(false) // report does not match filter
      .mockResolvedValueOnce(false) // campaign does not match filter
      .mockResolvedValueOnce(true); // malware matches filter

    const result = await callExecutor(bundle);

    expect(result.output_port).toBe('out');
    expect(result.bundle.objects).toHaveLength(2);
    expect(result.bundle.objects.find((o) => o.id === REPORT_ID)).toBeDefined(); // base element always included
    expect(result.bundle.objects.find((o) => o.id === CAMPAIGN_ID)).toBeUndefined(); // not matched, excluded
    expect(result.bundle.objects.find((o) => o.id === MALWARE_ID)).toBeDefined(); // matched element included
  });

  it('should return only base element (Report) deduplicated when filter matches Report itself', async () => {
    const report = createObject(REPORT_ID, 'report');
    const campaign = createObject(CAMPAIGN_ID, 'campaign');
    const malware = createObject(MALWARE_ID, 'malware');
    const bundle = createBundle(report, campaign, malware);

    vi.spyOn(filterUtils, 'isStixMatchFilterGroup')
      .mockResolvedValueOnce(true) // report matches filter
      .mockResolvedValueOnce(false) // campaign does not match filter
      .mockResolvedValueOnce(false); // malware does not match filter

    const result = await callExecutor(bundle);

    expect(result.output_port).toBe('out');
    expect(result.bundle.objects).toHaveLength(1); // Report deduplicated (baseData + matchedElement = same)
    expect(result.bundle.objects.find((o) => o.id === REPORT_ID)).toBeDefined();
    expect(result.bundle.objects.find((o) => o.id === CAMPAIGN_ID)).toBeUndefined();
    expect(result.bundle.objects.find((o) => o.id === MALWARE_ID)).toBeUndefined();
  });

  it('should return unmatch port with only unmatched elements (Campaign) without base element when nothing matches filter', async () => {
    const report = createObject(REPORT_ID, 'report');
    const campaign = createObject(CAMPAIGN_ID, 'campaign');
    const bundle = createBundle(report, campaign);

    vi.spyOn(filterUtils, 'isStixMatchFilterGroup')
      .mockResolvedValueOnce(false) // report does not match filter
      .mockResolvedValueOnce(false); // campaign does not match filter

    const result = await callExecutor(bundle);

    expect(result.output_port).toBe('unmatch');
    console.log('result', result.bundle.objects);
    expect(result.bundle.objects).toHaveLength(1); // only Campaign (unmatched), Report excluded
    expect(result.bundle.objects.find((o) => o.id === REPORT_ID)).toBeUndefined(); // base element NOT included on unmatch
    expect(result.bundle.objects.find((o) => o.id === CAMPAIGN_ID)).toBeDefined(); // unmatched element included
  });

  // Cas unmatch (2 objets): rien ne matche → unmatch: [Campaign, Malware] uniquement
  it('should return unmatch port with only unmatched elements (Campaign + Malware) without base element when nothing matches filter', async () => {
    const report = createObject(REPORT_ID, 'report');
    const campaign = createObject(CAMPAIGN_ID, 'campaign');
    const malware = createObject(MALWARE_ID, 'malware');
    const bundle = createBundle(report, campaign, malware);

    vi.spyOn(filterUtils, 'isStixMatchFilterGroup')
      .mockResolvedValueOnce(false) // report does not match filter
      .mockResolvedValueOnce(false) // campaign does not match filter
      .mockResolvedValueOnce(false); // malware does not match filter

    const result = await callExecutor(bundle);

    expect(result.output_port).toBe('unmatch');
    expect(result.bundle.objects).toHaveLength(2); // Campaign + Malware (unmatched), Report excluded
    expect(result.bundle.objects.find((o) => o.id === REPORT_ID)).toBeUndefined(); // base element NOT included on unmatch
    expect(result.bundle.objects.find((o) => o.id === CAMPAIGN_ID)).toBeDefined(); // unmatched element included
    expect(result.bundle.objects.find((o) => o.id === MALWARE_ID)).toBeDefined(); // unmatched element included
  });
});
