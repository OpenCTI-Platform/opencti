import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, getAuthUser, testContext, USER_EDITOR, USER_SECURITY } from '../../utils/testQuery';
import { addReport } from '../../../src/domain/report';
import { resolveUserByIdFromCache } from '../../../src/domain/user';
import { deleteElementById } from '../../../src/database/middleware';
import { fullEntitiesList } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';
import type { BasicStoreEntity } from '../../../src/types/store';
import { FilterMode } from '../../../src/generated/graphql';

/**
 * PoC #2 (merge-users investigation) - "alias" prototype.
 *
 * This test demonstrates, with real data, the central finding of the investigation:
 * redirecting a user id to another user id at the cache-resolution level (Family A)
 * is enough to change what is *displayed* (e.g. a representative/creator name), but it
 * has NO effect on *raw Elasticsearch queries* that filter directly on the stored id
 * (Family B, e.g. a "creator_id" filter). The alias is therefore not neutral: data
 * created by the "source" user remains invisible to any filter targeting the "target"
 * user, even though the source user itself now resolves as the target everywhere the
 * cache is used.
 *
 * Source user: USER_EDITOR (creates a report -> report.creator_id = USER_EDITOR.id)
 * Target user: USER_SECURITY (the alias destination)
 */
describe('Merge-users PoC #2 - alias redirection impact on fetching', () => {
  // `USER_EDITOR.id` / `USER_SECURITY.id` (from testQuery.ts) are STIX standard ids,
  // used only to look up the real internal ids below. `creator_id` on stored entities
  // (and the cache map) is keyed by the internal id, so the alias and the filters
  // below must use `internal_id`, not the standard id.
  let sourceUser: Awaited<ReturnType<typeof getAuthUser>>;
  let targetUser: Awaited<ReturnType<typeof getAuthUser>>;
  let reportId: string;

  beforeAll(async () => {
    sourceUser = await getAuthUser(USER_EDITOR.id);
    targetUser = await getAuthUser(USER_SECURITY.id);
    const report = await addReport(testContext, sourceUser, {
      name: 'Merge-users PoC alias - report created by source user',
      published: new Date().toISOString(),
      report_types: ['threat-report'],
    });
    reportId = report.id;
  });

  afterAll(async () => {
    delete process.env.MERGE_POC_ALIAS_MAP;
    if (reportId) {
      await deleteElementById(testContext, ADMIN_USER, reportId, ENTITY_TYPE_CONTAINER_REPORT);
    }
  });

  it('should NOT redirect anything when the alias flag is unset (default production behavior)', async () => {
    delete process.env.MERGE_POC_ALIAS_MAP;
    const resolved = await resolveUserByIdFromCache(testContext, sourceUser.internal_id) as { internal_id: string } | undefined;
    expect(resolved?.internal_id).toEqual(sourceUser.internal_id);
  });

  it('[Family A] should resolve the source user as the target user through the cache once the alias is enabled', async () => {
    process.env.MERGE_POC_ALIAS_MAP = JSON.stringify({ [sourceUser.internal_id]: targetUser.internal_id });
    const resolved = await resolveUserByIdFromCache(testContext, sourceUser.internal_id) as { internal_id: string } | undefined;
    // Family A works: any code path resolving a user id through the cache (e.g. a
    // "creator" representative shown in the UI) now sees the target user instead
    // of the source user, with no data rewrite involved.
    expect(resolved?.internal_id).toEqual(targetUser.internal_id);
  });

  it('[Family B] should NOT surface the report through a raw "creator_id = target" filter once the alias is enabled', async () => {
    process.env.MERGE_POC_ALIAS_MAP = JSON.stringify({ [sourceUser.internal_id]: targetUser.internal_id });
    // This filter is the standard filtering mechanism (buildEntityFilters) hitting
    // Elasticsearch directly on the stored `creator_id` field: it never goes through
    // resolveUserByIdFromCache, so the alias has zero effect here.
    const reportsForTargetUser = await fullEntitiesList<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_CONTAINER_REPORT], {
      filters: {
        mode: FilterMode.And,
        filters: [{ key: ['creator_id'], values: [targetUser.internal_id] }],
        filterGroups: [],
      },
    });
    expect(reportsForTargetUser.map((r) => r.id)).not.toContain(reportId);

    // Proof that the data is untouched: the report is still found when filtering on
    // the source id, exactly as if the alias did not exist.
    const reportsForSourceUser = await fullEntitiesList<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_CONTAINER_REPORT], {
      filters: {
        mode: FilterMode.And,
        filters: [{ key: ['creator_id'], values: [sourceUser.internal_id] }],
        filterGroups: [],
      },
    });
    expect(reportsForSourceUser.map((r) => r.id)).toContain(reportId);
  });
});
