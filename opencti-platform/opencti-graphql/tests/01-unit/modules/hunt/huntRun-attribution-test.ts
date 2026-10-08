import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getEntitiesMapFromCache, getEntityFromCache } from '../../../../src/database/cache';
import { getExistingRelations } from '../../../../src/database/middleware';
import { internalFindByIds } from '../../../../src/database/middleware-loader';
import { findByIds } from '../../../../src/modules/hunt/hunt-loaders';
import { findHuntRunById, isHuntRunConnectorCall } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import '../../../../src/modules/hunt/huntRun/huntRun-attribution';
import { getInputIds } from '../../../../src/schema/identifier';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA } from '../../../../src/schema/stixDomainObject';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../../../src/schema/stixRefRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../../src/schema/stixSightingRelationship';
import { getEntityValidatorCreation, getEntityValidatorUpdate, type ValidatorFn } from '../../../../src/schema/validator-register';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/modules/hunt/huntRun/huntRun-domain', () => ({
  findHuntRunById: vi.fn(),
  isHuntRunConnectorCall: vi.fn(),
}));

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  getExistingRelations: vi.fn(),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  internalFindByIds: vi.fn(),
}));

vi.mock('../../../../src/schema/identifier', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/schema/identifier')>(),
  getInputIds: vi.fn(),
}));

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/cache')>(),
  getEntityFromCache: vi.fn(),
  getEntitiesMapFromCache: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-loaders', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-loaders')>(),
  findByIds: vi.fn(),
}));

const markings = new Map([
  ['marking-green', { internal_id: 'marking-green', definition_type: 'TLP', x_opencti_order: 2 }],
  ['marking-definition--green', { internal_id: 'marking-green', definition_type: 'TLP', x_opencti_order: 2 }],
  ['marking-amber', { internal_id: 'marking-amber', definition_type: 'TLP', x_opencti_order: 3 }],
  ['marking-red', { internal_id: 'marking-red', definition_type: 'TLP', x_opencti_order: 4 }],
]);
const run = { internal_id: 'run-1', work_id: 'work-1', [RELATION_OBJECT_MARKING]: ['marking-amber'], [RELATION_GRANTED_TO]: ['organization-1'] };
const context = { workId: 'work-1', user_inside_platform_organization: true } as unknown as AuthContext;
const connector = (capabilities: string[], organizations: string[] = []) => ({
  id: 'connector',
  capabilities: capabilities.map((name) => ({ name })),
  organizations: organizations.map((id) => ({ internal_id: id })),
}) as unknown as AuthUser;
const restricting = connector(['KNOWLEDGE_KNUPDATE_KNORGARESTRICT']);
const evidence = (objectMarking: unknown[], objectOrganization: unknown[] = []) => ({ x_opencti_hunt_run_id: 'run-1', objectMarking, objectOrganization });

const validateCreation = (user: AuthUser, instance: Record<string, unknown>) => {
  return (getEntityValidatorCreation(ENTITY_TYPE_CONTAINER_OBSERVED_DATA) as ValidatorFn)(context, user, instance);
};
const validateUpdate = (instance: Record<string, unknown>, initial: Record<string, unknown>) => {
  return (getEntityValidatorUpdate(ENTITY_TYPE_CONTAINER_OBSERVED_DATA) as ValidatorFn)(context, restricting, instance, initial);
};
const validateSightingCreation = (instance: Record<string, unknown>) => {
  return (getEntityValidatorCreation(STIX_SIGHTING_RELATIONSHIP) as ValidatorFn)(context, restricting, instance);
};
const storedObject = (internalId: string, objectMarking: string[], granted: string[] = [], huntId?: string) => ({
  internal_id: internalId,
  standard_id: `${internalId}-standard`,
  [RELATION_OBJECT_MARKING]: objectMarking,
  [RELATION_GRANTED_TO]: granted,
  ...(huntId ? { x_opencti_hunt_id: huntId } : {}),
});

describe('Evidence attributed to a hunt run', () => {
  beforeEach(() => {
    vi.mocked(findHuntRunById).mockResolvedValue(run as never);
    vi.mocked(isHuntRunConnectorCall).mockResolvedValue(true);
    vi.mocked(getEntityFromCache).mockResolvedValue({ platform_organization: 'platform-organization' } as never);
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(markings as never);
    vi.mocked(findByIds).mockImplementation((async (_context: unknown, _user: unknown, ids: string[]) => ids.map((id) => ({ internal_id: id.replace('organization--', '') }))) as never);
    vi.mocked(getInputIds).mockReturnValue(['evidence-standard']);
    vi.mocked(internalFindByIds).mockResolvedValue([]);
    vi.mocked(getExistingRelations).mockResolvedValue([]);
  });

  it('should accept evidence at least as restricted as the run', async () => {
    expect(await validateCreation(restricting, evidence([{ internal_id: 'marking-red' }], [{ internal_id: 'organization-1' }]))).toBe(true);
    // Shared with no organization, the evidence is read by the platform organization only
    expect(await validateCreation(restricting, evidence([{ internal_id: 'marking-amber' }]))).toBe(true);
    // Before an upsert resolves them, the references are the ids the bundle names
    expect(await validateCreation(restricting, evidence(['marking-amber'], ['organization--organization-1']))).toBe(true);
  });

  it('should refuse evidence missing a marking of the run or shared with an organization the run is not', async () => {
    await expect(validateCreation(restricting, evidence([{ internal_id: 'marking-green' }]))).rejects.toThrow(/carries at least the markings of the run/);
    await expect(validateCreation(restricting, evidence(['marking-definition--green']))).rejects.toThrow(/carries at least the markings of the run/);
    await expect(validateCreation(restricting, evidence([{ internal_id: 'marking-amber' }], [{ internal_id: 'organization-2' }]))).rejects.toThrow(/no organization the run is not shared with/);
  });

  it('should count the organizations of a connector that cannot restrict access to organizations', async () => {
    const shared = { ...connector([], ['organization-2']), user_service_account: true } as AuthUser;
    await expect(validateCreation(shared, evidence([{ internal_id: 'marking-amber' }], [{ internal_id: 'organization-1' }]))).rejects.toThrow(/no organization the run is not shared with/);
    vi.mocked(getEntityFromCache).mockResolvedValue({} as never);
    expect(await validateCreation(shared, evidence([{ internal_id: 'marking-amber' }]))).toBe(true);
  });

  it('should check the access a stored object keeps once the evidence upserts into it', async () => {
    const amberShared = evidence([{ internal_id: 'marking-amber' }], [{ internal_id: 'organization-1' }]);
    vi.mocked(internalFindByIds).mockResolvedValue([storedObject('observed-1', ['marking-amber'], ['organization-2'])] as never);
    await expect(validateCreation(restricting, amberShared)).rejects.toThrow(/no organization the run is not shared with/);
    expect(internalFindByIds).toHaveBeenCalledWith(context, expect.anything(), ['evidence-standard'], { type: ENTITY_TYPE_CONTAINER_OBSERVED_DATA });
    // An incoming marking is not added to a stored one of lower confidence
    vi.mocked(internalFindByIds).mockResolvedValue([storedObject('observed-1', ['marking-green'])] as never);
    await expect(validateCreation(restricting, amberShared)).rejects.toThrow(/carries at least the markings of the run/);
    // Empty stored markings are filled by the incoming ones
    vi.mocked(internalFindByIds).mockResolvedValue([storedObject('observed-1', [])] as never);
    expect(await validateCreation(restricting, amberShared)).toBe(true);
    vi.mocked(internalFindByIds).mockResolvedValue([storedObject('observed-1', ['marking-red'], ['organization-1'])] as never);
    expect(await validateCreation(restricting, amberShared)).toBe(true);
  });

  it('should check the access of the sightings a sighting upserts into, never of the sighting a hunt keeps', async () => {
    const sighting = evidence([{ internal_id: 'marking-amber' }], [{ internal_id: 'organization-1' }]);
    vi.mocked(getExistingRelations).mockResolvedValue([storedObject('sighting-1', ['marking-amber'], ['organization-2'])] as never);
    await expect(validateSightingCreation(sighting)).rejects.toThrow(/no organization the run is not shared with/);
    const huntSighting = storedObject('sighting-hunt', ['marking-green'], ['organization-2'], 'hunt-1');
    vi.mocked(getExistingRelations).mockResolvedValue([huntSighting] as never);
    expect(await validateSightingCreation(sighting)).toBe(true);
    // Naming its id merges into it
    vi.mocked(getInputIds).mockReturnValue(['evidence-standard', 'sighting-hunt-standard']);
    await expect(validateSightingCreation(sighting)).rejects.toThrow(/carries at least the markings of the run/);
  });

  it('should check the stored access of an object attributed to a run, never the clearing of an attribution', async () => {
    expect(await validateUpdate({ x_opencti_hunt_run_id: 'run-1' }, { [RELATION_OBJECT_MARKING]: ['marking-amber'], [RELATION_GRANTED_TO]: ['organization-1'] })).toBe(true);
    await expect(validateUpdate({ x_opencti_hunt_run_id: 'run-1' }, { [RELATION_OBJECT_MARKING]: [] })).rejects.toThrow(/carries at least the markings of the run/);
    expect(await validateUpdate({ x_opencti_hunt_run_id: '' }, { x_opencti_hunt_run_id: 'run-1', [RELATION_OBJECT_MARKING]: [] })).toBe(true);
  });

  it('should refuse to attribute an object to a run in the change that sets its markings or organizations', async () => {
    const stored = { [RELATION_OBJECT_MARKING]: ['marking-amber'], [RELATION_GRANTED_TO]: ['organization-1'] };
    await expect(validateUpdate({ x_opencti_hunt_run_id: 'run-1', objectMarking: [] }, stored)).rejects.toThrow(/in a change of its own/);
    await expect(validateUpdate({ x_opencti_hunt_run_id: 'run-1', objectOrganization: ['organization-2'] }, stored)).rejects.toThrow(/in a change of its own/);
  });
});
