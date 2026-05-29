import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, getAuthUser, testContext, USER_DISINFORMATION_ANALYST, USER_EDITOR } from '../../utils/testQuery';
import { addDraftWorkspace } from '../../../src/modules/draftWorkspace/draftWorkspace-domain';
import { meEditField } from '../../../src/domain/user';
import { deleteElementById } from '../../../src/database/middleware';
import { internalLoadById } from '../../../src/database/middleware-loader';
import { executionContext } from '../../../src/utils/access';
import { checkDraftInContext } from '../../../src/http/httpServer-draft';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../../../src/modules/draftWorkspace/draftWorkspace-types';
import { ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import type { AuthUser } from '../../../src/types/user';
import type { DraftWorkspaceAddInput } from '../../../src/generated/graphql';

// Regression tests for https://github.com/OpenCTI-Platform/opencti/issues/16273
// A user must always be able to exit a draft context (a navigation action on their own user
// entity), even when they do not have edit access on the draft they entered.
describe('Drafts workspace exit testing', () => {
  let editorAuthUser: AuthUser;
  let analystAuthUser: AuthUser;
  let viewableDraftId: string;
  let restrictedDraftId: string;

  beforeAll(async () => {
    editorAuthUser = await getAuthUser(USER_EDITOR.id);
    analystAuthUser = await getAuthUser(USER_DISINFORMATION_ANALYST.id);

    // A draft where the analyst only has "view" access (can enter/see, but cannot edit)
    const viewableInput: DraftWorkspaceAddInput = {
      name: 'Draft exit test - viewable',
      authorized_members: [
        { id: editorAuthUser.internal_id, access_right: 'admin' },
        { id: analystAuthUser.internal_id, access_right: 'view' },
      ],
    };
    viewableDraftId = (await addDraftWorkspace(testContext, editorAuthUser, viewableInput)).id;

    // A draft where the analyst has no access at all
    const restrictedInput: DraftWorkspaceAddInput = {
      name: 'Draft exit test - restricted',
      authorized_members: [
        { id: editorAuthUser.internal_id, access_right: 'admin' },
      ],
    };
    restrictedDraftId = (await addDraftWorkspace(testContext, editorAuthUser, restrictedInput)).id;
  });

  afterAll(async () => {
    if (viewableDraftId) {
      await deleteElementById(testContext, ADMIN_USER, viewableDraftId, ENTITY_TYPE_DRAFT_WORKSPACE);
    }
    if (restrictedDraftId) {
      await deleteElementById(testContext, ADMIN_USER, restrictedDraftId, ENTITY_TYPE_DRAFT_WORKSPACE);
    }
    // Make sure the analyst is not left in any draft context
    await meEditField(testContext, analystAuthUser, analystAuthUser.id, [{ key: 'draft_context', value: '' }]);
  });

  it('should let a view-only user exit a draft they cannot edit', async () => {
    // The analyst can access (view) the draft, so request execution is allowed in that context
    const analystInDraft = { ...analystAuthUser, draft_context: viewableDraftId };
    const analystDraftContext = executionContext('testing', analystInDraft, viewableDraftId);
    await expect(checkDraftInContext(analystDraftContext)).resolves.not.toThrow();

    // Exiting the draft must not be gated by the draft edit access check
    await expect(
      meEditField(analystDraftContext, analystInDraft, analystAuthUser.id, [{ key: 'draft_context', value: '' }]),
    ).resolves.toBeDefined();

    const reloadedAnalyst = await internalLoadById(testContext, ADMIN_USER, analystAuthUser.id, { type: ENTITY_TYPE_USER });
    expect((reloadedAnalyst as unknown as AuthUser).draft_context).toBeFalsy();
  });

  it('should self-heal users stuck in a draft they cannot access', async () => {
    // Force the analyst into a draft they cannot access (simulating a draft created via API)
    await meEditField(testContext, analystAuthUser, analystAuthUser.id, [{ key: 'draft_context', value: [restrictedDraftId] }]);
    const stuckAnalyst = await getAuthUser(USER_DISINFORMATION_ANALYST.id);
    expect(stuckAnalyst.draft_context).toEqual(restrictedDraftId);

    const stuckContext = executionContext('testing', stuckAnalyst, restrictedDraftId);
    await expect(checkDraftInContext(stuckContext)).rejects.toThrowError(`Draft ${restrictedDraftId} cannot be found`);

    // The draft context must have been removed from the user so they are no longer trapped
    const reloadedAnalyst = await internalLoadById(testContext, ADMIN_USER, analystAuthUser.id, { type: ENTITY_TYPE_USER });
    expect((reloadedAnalyst as unknown as AuthUser).draft_context).toBeFalsy();
  });
});
