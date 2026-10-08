import type { FileHandle } from 'fs/promises';
import { Readable } from 'node:stream';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { addLabel } from '../../../../src/domain/label';
import { findByIds } from '../../../../src/modules/hunt/hunt-loaders';
import { parseHuntPack, planHuntPackImport, resolveHuntPackLabels } from '../../../../src/modules/hunt/hunt-pack';
import type { StixHunt } from '../../../../src/modules/hunt/hunt-types';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import type { AuthUser } from '../../../../src/types/user';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/modules/hunt/hunt-loaders', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-loaders')>(),
  findByIds: vi.fn(),
}));

vi.mock('../../../../src/domain/label', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/domain/label')>(),
  addLabel: vi.fn(),
}));

const ORGANIZATION = 'identity--7b82b010-b1c0-4dae-981f-7756374a17df';
const organization = { internal_id: 'organization-1', standard_id: ORGANIZATION, entity_type: 'Organization' };
const restrictedHunt = (granted: string[]) => ({
  id: 'hunt--1',
  type: 'hunt',
  name: 'Restricted hunt',
  sigma_rule: 'title: t',
  extensions: { [STIX_EXT_OCTI]: { granted_refs: granted } },
}) as unknown as StixHunt;
const knownOrganizations = () => vi.mocked(findByIds).mockImplementation(async (_context, _user, ids) => (
  ids.includes(ORGANIZATION) ? [organization] : []
) as never);

describe('Organizations of a pack hunt', () => {
  afterEach(() => {
    vi.mocked(findByIds).mockReset();
  });

  it('should restrict the imported hunt to the organizations it was restricted to', async () => {
    knownOrganizations();
    const plan = await planHuntPackImport(testContext, ADMIN_USER, restrictedHunt([ORGANIZATION]), new Map());
    expect(plan.blocked).toBe(false);
    expect(plan.input.objectOrganization).toEqual(['organization-1']);
    expect(findByIds).toHaveBeenCalledWith(testContext, ADMIN_USER, [ORGANIZATION], { type: 'Organization' });
  });

  it('should skip a hunt restricted to an organization unknown here, as a hunt with unknown markings', async () => {
    knownOrganizations();
    const unknown = 'identity--0c9f3c1e-2b4a-4d6e-8f1a-3b5c7d9e1f20';
    const plan = await planHuntPackImport(testContext, ADMIN_USER, restrictedHunt([ORGANIZATION, unknown]), new Map());
    expect(plan.blocked).toBe(true);
    expect(plan.unresolved).toEqual([unknown]);
  });

  it('should refuse a restricted hunt to a user who cannot restrict access to organizations', async () => {
    knownOrganizations();
    const analyst = { ...ADMIN_USER, capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }] } as AuthUser;
    await expect(planHuntPackImport(testContext, analyst, restrictedHunt([ORGANIZATION]), new Map()))
      .rejects.toThrow('only a user who can restrict access to organizations can import it');
    // A hunt without organizations is imported as before
    const plan = await planHuntPackImport(testContext, analyst, restrictedHunt([]), new Map());
    expect(plan.blocked).toBe(false);
    expect(plan.input.objectOrganization).toBeUndefined();
  });
});

describe('Techniques and markings of a pack hunt', () => {
  afterEach(() => {
    vi.mocked(findByIds).mockReset();
  });

  it('should take a technique and a marking named by another of their STIX ids as resolved', async () => {
    const technique = { internal_id: 'technique-1', standard_id: 'attack-pattern--a1', x_opencti_stix_ids: ['attack-pattern--b2'], entity_type: 'Attack-Pattern' };
    const marking = { internal_id: 'marking-1', standard_id: 'marking-definition--c3', x_opencti_stix_ids: ['marking-definition--d4'], entity_type: 'Marking-Definition' };
    vi.mocked(findByIds).mockImplementation(async (_context, _user, ids) => [technique, marking].filter((element) => (
      ids.includes(element.standard_id) || element.x_opencti_stix_ids.some((id) => ids.includes(id))
    )) as never);
    const hunt = {
      id: 'hunt--1',
      type: 'hunt',
      name: 'Hunt of another platform',
      sigma_rule: 'title: t',
      technique_refs: ['attack-pattern--b2'],
      // The same marking, named twice
      object_marking_refs: ['marking-definition--d4', 'marking-definition--d4'],
    } as unknown as StixHunt;
    const plan = await planHuntPackImport(testContext, ADMIN_USER, hunt, new Map());
    expect(plan.unresolved).toEqual([]);
    expect(plan.blocked).toBe(false);
    expect(plan.input.huntTechniques).toEqual(['technique-1']);
    expect(plan.input.objectMarking).toEqual(['marking-1']);
  });

  it('should still skip a hunt with a marking unknown here', async () => {
    vi.mocked(findByIds).mockResolvedValue([] as never);
    const hunt = { id: 'hunt--2', type: 'hunt', name: 'Marked hunt', sigma_rule: 'title: t', object_marking_refs: ['marking-definition--e5'] } as unknown as StixHunt;
    const plan = await planHuntPackImport(testContext, ADMIN_USER, hunt, new Map());
    expect(plan.blocked).toBe(true);
    expect(plan.unresolved).toEqual(['marking-definition--e5']);
  });
});

const packOf = (hunts: Record<string, unknown>[]) => Promise.resolve({
  createReadStream: () => Readable.from([Buffer.from(JSON.stringify({ type: 'bundle', id: 'bundle--1', objects: hunts }))]),
} as unknown as FileHandle);
const labelledHunt = (index: number, labels: string[]) => ({ id: `hunt--${index}`, type: 'hunt', name: `Hunt ${index}`, sigma_rule: 'title: t', labels });

describe('Labels of a pack hunt', () => {
  afterEach(() => {
    vi.mocked(addLabel).mockReset();
  });

  it('should refuse a pack whose labels are too many or too long before anything is written', async () => {
    const many = Array.from({ length: 51 }, (_, index) => `label-${index}`);
    await expect(parseHuntPack(packOf([labelledHunt(1, many)]))).rejects.toThrow('has more than 50 labels or a label longer than 256 characters');
    await expect(parseHuntPack(packOf([labelledHunt(1, ['x'.repeat(257)])]))).rejects.toThrow('has more than 50 labels or a label longer than 256 characters');
    const spread = Array.from({ length: 11 }, (_, hunt) => labelledHunt(hunt, Array.from({ length: 50 }, (__, index) => `label-${hunt}-${index}`)));
    await expect(parseHuntPack(packOf(spread))).rejects.toThrow('limited to 500 distinct labels');
    const { hunts } = await parseHuntPack(packOf([labelledHunt(1, many.slice(0, 50)), labelledHunt(2, many.slice(0, 50))]));
    expect(hunts).toHaveLength(2);
    expect(addLabel).not.toHaveBeenCalled();
  });

  it('should write the labels a few at a time, each label once for the whole pack', async () => {
    let writing = 0;
    let mostAtOnce = 0;
    vi.mocked(addLabel).mockImplementation((async (_context: unknown, _user: unknown, { value }: { value: string }) => {
      writing += 1;
      mostAtOnce = Math.max(mostAtOnce, writing);
      await new Promise((resolve) => {
        setTimeout(resolve, 1);
      });
      writing -= 1;
      return { internal_id: `id-${value}` };
    }) as never);
    const labels = Array.from({ length: 35 }, (_, index) => `label-${index}`);
    const resolved = new Map<string, string>();
    expect(await resolveHuntPackLabels(testContext, ADMIN_USER, [...labels, labels[0]], resolved)).toEqual(labels.map((label) => `id-${label}`));
    expect(addLabel).toHaveBeenCalledTimes(35);
    expect(mostAtOnce).toBeLessThanOrEqual(10);
    // A later hunt of the pack reuses the labels already written
    expect(await resolveHuntPackLabels(testContext, ADMIN_USER, ['label-3', 'label-new'], resolved)).toEqual(['id-label-3', 'id-label-new']);
    expect(addLabel).toHaveBeenCalledTimes(36);
  });
});
