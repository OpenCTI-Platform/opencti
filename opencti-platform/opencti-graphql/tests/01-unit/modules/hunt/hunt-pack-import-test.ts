import { afterEach, describe, expect, it, vi } from 'vitest';
import { findByIds } from '../../../../src/modules/hunt/hunt-loaders';
import { planHuntPackImport } from '../../../../src/modules/hunt/hunt-pack';
import type { StixHunt } from '../../../../src/modules/hunt/hunt-types';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import type { AuthUser } from '../../../../src/types/user';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/modules/hunt/hunt-loaders', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-loaders')>(),
  findByIds: vi.fn(),
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
