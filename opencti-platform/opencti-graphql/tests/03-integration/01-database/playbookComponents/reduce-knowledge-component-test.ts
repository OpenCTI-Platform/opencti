import { describe, expect, it, vi, afterEach, beforeEach } from 'vitest';
import type { StixBundle, StixObject, StixOpenctiExtension } from '../../../../src/types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import { PLAYBOOK_REDUCING_COMPONENT } from '../../../../src/modules/playbook/playbook-components';
import * as access from '../../../../src/utils/access';
import * as filterUtils from '../../../../src/utils/filtering/filtering-stix/stix-filtering';
import * as stixLoader from '../../../../src/database/middleware';

const REPORT_ID = 'report--5f78a68b-2c4d-5e6f-beaa-7b987b0e7165';
const CAMPAIGN_ID = 'campaign--fdcacc8e-de4d-5a13-8886-401d363664fd';
const MALWARE_ID = 'malware--aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';

const createBasicObject = (id: string, type: string, extra: object = {}): StixObject =>
  ({
    id,
    spec_version: '2.1',
    type,
    extensions: {
      [STIX_EXT_OCTI]: {
        extension_type: 'property-extension',
        id: `ext-${id}`,
        type,
      } as StixOpenctiExtension,
    },
    ...extra,
  } as StixObject);

const createReport = (objectRefs: string[]): StixObject =>
  createBasicObject(REPORT_ID, 'report', {
    name: 'Test Report',
    published: '2026-01-01T00:00:00.000Z',
    object_refs: objectRefs,
  });

const createBundle = (report: StixObject, ...extras: StixObject[]): StixBundle => ({
  id: 'bundle--00000000-0000-0000-0000-000000000001',
  spec_version: '2.1',
  type: 'bundle',
  objects: [report, ...extras],
} as StixBundle);

const makePlaybookNode = (filters: object) => ({
  id: 'playbook-node-reduce',
  name: 'reduce-node',
  component_id: 'PLAYBOOK_REDUCING_COMPONENT',
  configuration: {
    filters: JSON.stringify(filters),
  },
});

const EMPTY_FILTER = {};

const callExecutor = (bundle: StixBundle, filters: object = EMPTY_FILTER) =>
  PLAYBOOK_REDUCING_COMPONENT.executor({
    dataInstanceId: REPORT_ID,
    eventId: '',
    executionId: '',
    playbookId: '',
    previousPlaybookNodeId: undefined,
    previousStepBundle: null as StixBundle | null,
    bundle,
    playbookNode: makePlaybookNode(filters),
  });

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('PLAYBOOK_REDUCING_COMPONENT', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(access, 'executionContext').mockReturnValue({} as any);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('when base object has no object_refs', () => {
    it('should return unmatch port when object_refs is empty', async () => {
      const bundle = createBundle(createReport([]));

      const result = await callExecutor(bundle);

      expect(result.output_port).toBe('unmatch');
      expect(result.bundle).toBe(bundle);
    });
  });

  describe('when all object_refs match the filter', () => {
    it('should return out port and keep all refs', async () => {
      const campaign = createBasicObject(CAMPAIGN_ID, 'campaign');
      const finalBundle = createBundle(createReport([CAMPAIGN_ID]), campaign);

      vi.spyOn(stixLoader, 'stixLoadById').mockResolvedValue(campaign as any);
      vi.spyOn(filterUtils, 'isStixMatchFilterGroup').mockResolvedValue(true);

      const result = await callExecutor(finalBundle, { mode: 'and', filters: [], filterGroups: [] });

      expect(result.output_port).toBe('out');

      const report = result.bundle.objects.find((o) => o.id === REPORT_ID) as StixObject & { object_refs: string[] };
      expect(report.object_refs).toContain(CAMPAIGN_ID);
      expect(report.object_refs).toHaveLength(1);
      expect(result.bundle.objects).toHaveLength(2);
    });

    it('should keep all refs when multiple objects all match', async () => {
      const campaign = createBasicObject(CAMPAIGN_ID, 'campaign');
      const malware = createBasicObject(MALWARE_ID, 'malware');
      const bundle = createBundle(createReport([CAMPAIGN_ID, MALWARE_ID]), campaign, malware);

      vi.spyOn(stixLoader, 'stixLoadById')
        .mockResolvedValueOnce(campaign as any)
        .mockResolvedValueOnce(malware as any);
      vi.spyOn(filterUtils, 'isStixMatchFilterGroup').mockResolvedValue(true);

      const result = await callExecutor(bundle);

      expect(result.output_port).toBe('out');

      const report = result.bundle.objects.find((o) => o.id === REPORT_ID) as StixObject & { object_refs: string[] };
      expect(report.object_refs).toContain(CAMPAIGN_ID);
      expect(report.object_refs).toContain(MALWARE_ID);
      expect(report.object_refs).toHaveLength(2);
      expect(result.bundle.objects).toHaveLength(3);
    });
  });

  describe('when no object_refs match the filter', () => {
    it('should return unmatch port and original bundle', async () => {
      const campaign = createBasicObject(CAMPAIGN_ID, 'campaign');
      const bundle = createBundle(createReport([CAMPAIGN_ID]), campaign);

      vi.spyOn(stixLoader, 'stixLoadById').mockResolvedValue(campaign as any);
      vi.spyOn(filterUtils, 'isStixMatchFilterGroup').mockResolvedValue(false);

      const result = await callExecutor(bundle);

      expect(result.output_port).toBe('unmatch');
      expect(result.bundle).toBe(bundle);
    });
  });

  describe('when only some object_refs match the filter', () => {
    it('should keep only matching refs and objects', async () => {
      const campaign = createBasicObject(CAMPAIGN_ID, 'campaign');
      const malware = createBasicObject(MALWARE_ID, 'malware');
      const bundle = createBundle(createReport([CAMPAIGN_ID, MALWARE_ID]), campaign, malware);

      vi.spyOn(stixLoader, 'stixLoadById')
        .mockResolvedValueOnce(campaign as any)
        .mockResolvedValueOnce(malware as any);
      vi.spyOn(filterUtils, 'isStixMatchFilterGroup')
        .mockResolvedValueOnce(true)
        .mockResolvedValueOnce(false);

      const result = await callExecutor(bundle);

      expect(result.output_port).toBe('out');

      const report = result.bundle.objects.find((o) => o.id === REPORT_ID) as StixObject & { object_refs: string[] };
      expect(report.object_refs).toContain(CAMPAIGN_ID);
      expect(report.object_refs).not.toContain(MALWARE_ID);
      expect(report.object_refs).toHaveLength(1);
      expect(result.bundle.objects).toHaveLength(2);
      expect(result.bundle.objects.map((o) => o.id)).not.toContain(MALWARE_ID);
    });
  });
});
