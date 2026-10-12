import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as loader from '../../../../src/database/middleware-loader';
import { validateEnrichmentInvestigation } from '../../../../src/modules/workspace/investigation-enrichment';
import { buildStandardUser, testContext } from '../../../utils/testQuery';

/**
 * Build a standard user holding exactly the given capabilities, with an id usable in restricted members.
 */
const userWith = (capabilities: string[], id = '98ec0c6a-13ce-5e39-b486-354fe4a7084f') => {
  const user = buildStandardUser([], [], capabilities.map((name) => ({ name })));
  return { ...user, internal_id: id, id };
};

/**
 * Build a fake investigation workspace with the given restricted members.
 */
const investigation = (restricted_members: any[] = []) => ({ id: 'inv-1', entity_type: 'Workspace', type: 'investigation', restricted_members }) as any;

describe('validateEnrichmentInvestigation', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('should refuse an unknown or invisible investigation', async () => {
    vi.spyOn(loader, 'storeLoadById').mockResolvedValue(undefined as any);
    await expect(validateEnrichmentInvestigation(testContext, userWith(['INVESTIGATION_INUPDATE']), 'inv-1')).rejects.toThrow('Investigation not found');
  });

  it('should refuse a dashboard', async () => {
    vi.spyOn(loader, 'storeLoadById').mockResolvedValue({ ...investigation(), type: 'dashboard' });
    await expect(validateEnrichmentInvestigation(testContext, userWith(['INVESTIGATION_INUPDATE']), 'inv-1')).rejects.toThrow('Investigation not found');
  });

  it('should refuse a user without the investigation update capability', async () => {
    vi.spyOn(loader, 'storeLoadById').mockResolvedValue(investigation());
    await expect(validateEnrichmentInvestigation(testContext, userWith(['KNOWLEDGE_KNENRICHMENT']), 'inv-1')).rejects.toThrow('You are not allowed to do this.');
  });

  it('should refuse a user without the investigation update capability before loading', async () => {
    const spy = vi.spyOn(loader, 'storeLoadById').mockResolvedValue(undefined as any);
    await expect(validateEnrichmentInvestigation(testContext, userWith(['KNOWLEDGE_KNENRICHMENT']), 'inv-1')).rejects.toThrow('You are not allowed to do this.');
    expect(spy).not.toHaveBeenCalled();
  });

  it('should refuse a view-only member', async () => {
    const user = userWith(['INVESTIGATION_INUPDATE']);
    vi.spyOn(loader, 'storeLoadById').mockResolvedValue(investigation([{ id: user.id, access_right: 'view' }]));
    await expect(validateEnrichmentInvestigation(testContext, user, 'inv-1')).rejects.toThrow('You are not allowed to do this.');
  });

  it('should accept an edit member', async () => {
    const user = userWith(['INVESTIGATION_INUPDATE']);
    vi.spyOn(loader, 'storeLoadById').mockResolvedValue(investigation([{ id: user.id, access_right: 'edit' }]));
    await expect(validateEnrichmentInvestigation(testContext, user, 'inv-1')).resolves.toMatchObject({ id: 'inv-1' });
  });

  it('should require the enrichment capability when asked', async () => {
    vi.spyOn(loader, 'storeLoadById').mockResolvedValue(investigation());
    await expect(validateEnrichmentInvestigation(testContext, userWith(['INVESTIGATION_INUPDATE']), 'inv-1', { checkEnrichmentCapability: true }))
      .rejects.toThrow('You are not allowed to do this.');
  });
});
