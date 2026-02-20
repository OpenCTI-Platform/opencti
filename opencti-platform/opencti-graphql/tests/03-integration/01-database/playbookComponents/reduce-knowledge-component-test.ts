import { describe, expect, it, vi, afterEach, beforeEach } from 'vitest';
import type { StixBundle, StixObject, StixOpenctiExtension } from '../../../../src/types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import { PLAYBOOK_REDUCING_COMPONENT } from '../../../../src/modules/playbook/playbook-components';
import * as access from '../../../../src/utils/access';
import * as filterUtils from '../../../../src/utils/filtering/filtering-stix/stix-filtering';

const REPORT_ID = 'report--5f78a68b-2c4d-5e6f-beaa-7b987b0e7165';
const CAMPAIGN_ID = 'campaign--fdcacc8e-de4d-5a13-8886-401d363664fd';

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

  it('should keep objects that match the filter alongside the base element', async () => {
    const report = createObject(REPORT_ID, 'report');
    const campaign = createObject(CAMPAIGN_ID, 'campaign');
    const bundle = createBundle(report, campaign);

    vi.spyOn(filterUtils, 'isStixMatchFilterGroup')
      .mockResolvedValueOnce(false) // report (base element, always kept regardless)
      .mockResolvedValueOnce(true); // campaign matches

    const result = await callExecutor(bundle);

    expect(result.output_port).toBe('out');
    expect(result.bundle.objects).toHaveLength(2);
    expect(result.bundle.objects.find((o) => o.id === REPORT_ID)).toBeDefined();
    expect(result.bundle.objects.find((o) => o.id === CAMPAIGN_ID)).toBeDefined();
  });

  it('should remove objects that do not match the filter', async () => {
    const report = createObject(REPORT_ID, 'report');
    const campaign = createObject(CAMPAIGN_ID, 'campaign');
    const bundle = createBundle(report, campaign);

    vi.spyOn(filterUtils, 'isStixMatchFilterGroup')
      .mockResolvedValueOnce(false) // report (base element, always kept regardless)
      .mockResolvedValueOnce(false); // campaign does not match

    const result = await callExecutor(bundle);

    expect(result.output_port).toBe('out');
    expect(result.bundle.objects).toHaveLength(1);
    expect(result.bundle.objects.find((o) => o.id === REPORT_ID)).toBeDefined();
    expect(result.bundle.objects.find((o) => o.id === CAMPAIGN_ID)).toBeUndefined();
  });
});
