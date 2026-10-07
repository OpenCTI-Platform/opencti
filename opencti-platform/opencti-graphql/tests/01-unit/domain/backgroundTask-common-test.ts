import { afterEach, describe, expect, it, vi } from 'vitest';
import { ACTION_TYPE_ADD, ACTION_TYPE_REPLACE, ACTION_TYPE_DELETE, checkActionValidity, TASK_TYPE_QUERY, ACTION_TYPE_MERGE } from '../../../src/domain/backgroundTask-common';
import { ADMIN_USER, buildStandardUser, testContext } from '../../utils/testQuery';
import { isFeatureEnabled } from '../../../src/config/conf';
import { ENTITY_TYPE_VOCABULARY } from '../../../src/modules/vocabulary/vocabulary-types';
import { ENTITY_TYPE_WORKSPACE } from '../../../src/modules/workspace/workspace-types';
import { ENTITY_TYPE_NOTIFICATION } from '../../../src/modules/notification/notification-types';
import { TYPE_FILTER, USER_ID_FILTER } from '../../../src/utils/filtering/filtering-constants';
import { BackgroundTaskScope } from '../../../src/generated/graphql';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual: object = await importOriginal();
  return {
    ...actual,
    isFeatureEnabled: vi.fn(() => true),
  };
});

const filterEntityType = (entityType: string) => {
  return JSON.stringify({
    mode: 'and',
    filters: [
      {
        key: [TYPE_FILTER],
        values: [entityType],
        operator: 'eq',
        mode: 'or',
      },
    ],
    filterGroups: [],
  });
};

const filterWorkspaceType = (type: 'dashboard' | 'investigation') => {
  return JSON.stringify({
    mode: 'and',
    filters: [
      {
        key: [TYPE_FILTER],
        values: [ENTITY_TYPE_WORKSPACE],
        operator: 'eq',
        mode: 'or',
      },
      {
        key: ['type'],
        values: [type],
        operator: 'eq',
        mode: 'or',
      },
    ],
    filterGroups: [],
  });
};

describe('Background task validity check (checkActionValidity)', () => {
  const userParticipate = buildStandardUser([], [], [{ name: 'KNOWLEDGE_KNPARTICIPATE' }]);
  const userUpdate = buildStandardUser([], [], [{ name: 'KNOWLEDGE_KNUPDATE' }]);
  const userDelete = buildStandardUser([], [], [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }]);
  const userMerge = buildStandardUser([], [], [{ name: 'KNOWLEDGE_KNUPDATE_KNMERGE' }]);

  const userEditor = buildStandardUser([], [], [
    { name: 'KNOWLEDGE_KNUPDATE_KNDELETE' },
    { name: 'KNOWLEDGE_KNUPDATE_KNMERGE' },
    { name: 'KNOWLEDGE_KNASKIMPORT' },
    { name: 'EXPLORE_EXUPDATE_EXDELETE' },
    { name: 'EXPLORE_EXUPDATE_PUBLISH' },
    { name: 'INVESTIGATION_INUPDATE_INDELETE' },
  ]);

  describe('Check actions validity', () => {
    const user = userEditor;
    const type = TASK_TYPE_QUERY;

    it('should not throw an error if there are several actions on the same field and none of these actions is a replace', async () => {
      const input = {
        actions: [
          { type: ACTION_TYPE_ADD, field: 'object-label', value: ['label1'] },
          { type: ACTION_TYPE_ADD, field: 'object-label', value: ['label2'] },
          { type: ACTION_TYPE_REPLACE, field: 'object-marking', value: ['markingA'] },
        ],
        filters: filterEntityType(ENTITY_TYPE_CONTAINER_REPORT),
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, BackgroundTaskScope.Knowledge, type);
      }).not.toThrowError();
    });

    it('should throw an error if there are several actions on the same field and one action is a replace', async () => {
      const input = {
        actions: [
          { type: ACTION_TYPE_ADD, field: 'object-label', value: ['label1'] },
          { type: ACTION_TYPE_REPLACE, field: 'object-label', value: ['label2'] },
        ],
        filters: filterEntityType(ENTITY_TYPE_CONTAINER_REPORT),
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, BackgroundTaskScope.Knowledge, type);
      }).rejects.toThrowError('A single task cannot perform several actions on the same field if one action is a replace.');
    });

    it('should throw an error if there are several replace actions on the same field', async () => {
      const input = {
        actions: [
          { type: ACTION_TYPE_REPLACE, field: 'object-label', value: ['label1'] },
          { type: ACTION_TYPE_REPLACE, field: 'object-label', value: ['label2'] },
        ],
        filters: filterEntityType(ENTITY_TYPE_CONTAINER_REPORT),
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, BackgroundTaskScope.Knowledge, type);
      }).rejects.toThrowError('A single task cannot perform several actions on the same field if one action is a replace.');
    });
  });

  describe('Workflow status actions', () => {
    const type = TASK_TYPE_QUERY;
    const scope = BackgroundTaskScope.Knowledge;
    const bypassAction = {
      type: ACTION_TYPE_REPLACE,
      context: { field: 'x_opencti_workflow_id', values: ['status-id'], options: { applyTransitionActions: true } },
    };
    const buildInput = (actions: object[]) => ({ actions, filters: filterEntityType(ENTITY_TYPE_CONTAINER_REPORT) });

    afterEach(() => {
      vi.mocked(isFeatureEnabled).mockReturnValue(true);
    });

    it('should accept a workflow bypass action for a bypass user', async () => {
      await expect(checkActionValidity(testContext, ADMIN_USER, buildInput([bypassAction]), scope, type)).resolves.toEqual(undefined);
    });

    it('should throw an error if the ENTITIES_WORKFLOW feature flag is disabled', async () => {
      vi.mocked(isFeatureEnabled).mockReturnValue(false);
      await expect(checkActionValidity(testContext, ADMIN_USER, buildInput([bypassAction]), scope, type))
        .rejects.toThrowError('ENTITIES_WORKFLOW is disabled');
    });

    it('should throw an error if the task is created in a draft', async () => {
      const draftContext = { ...testContext, draft_context: 'draft-id' };
      await expect(checkActionValidity(draftContext, ADMIN_USER, buildInput([bypassAction]), scope, type))
        .rejects.toThrowError('Cannot change workflow status in draft');
    });

    it('should throw an error if another action targets the workflow status', async () => {
      const statusAction = { type: ACTION_TYPE_REPLACE, context: { field: 'x_opencti_workflow_id', values: ['other-status-id'] } };
      await expect(checkActionValidity(testContext, ADMIN_USER, buildInput([bypassAction, statusAction]), scope, type))
        .rejects.toThrowError('A single task cannot perform several actions on the workflow status');
    });

    it('should throw an error if the user has no BYPASS capability', async () => {
      await expect(checkActionValidity(testContext, userUpdate, buildInput([bypassAction]), scope, type))
        .rejects.toThrowError('You are not allowed to do this.');
    });

    it('should throw an error if a workflow bypass action has no target status', async () => {
      const emptyBypassAction = { ...bypassAction, context: { ...bypassAction.context, values: [] } };
      await expect(checkActionValidity(testContext, ADMIN_USER, buildInput([emptyBypassAction]), scope, type))
        .rejects.toThrowError('A workflow status action requires exactly one target status');
    });

    it('should accept a workflow transition action for a user without BYPASS capability', async () => {
      const transitionAction = { type: ACTION_TYPE_REPLACE, context: { field: 'x_opencti_workflow_id', values: [], options: { eventName: 'approve' } } };
      await expect(checkActionValidity(testContext, userUpdate, buildInput([transitionAction]), scope, type)).resolves.toEqual(undefined);
    });

    it('should throw an error for a workflow transition action if the ENTITIES_WORKFLOW feature flag is disabled', async () => {
      vi.mocked(isFeatureEnabled).mockReturnValue(false);
      const transitionAction = { type: ACTION_TYPE_REPLACE, context: { field: 'x_opencti_workflow_id', values: [], options: { eventName: 'approve' } } };
      await expect(checkActionValidity(testContext, userUpdate, buildInput([transitionAction]), scope, type))
        .rejects.toThrowError('ENTITIES_WORKFLOW is disabled');
    });

    it('should not check workflow rules for a plain status replace', async () => {
      vi.mocked(isFeatureEnabled).mockReturnValue(false);
      const statusAction = { type: ACTION_TYPE_REPLACE, context: { field: 'x_opencti_workflow_id', values: ['status-id'] } };
      await expect(checkActionValidity(testContext, userUpdate, buildInput([statusAction]), scope, type)).resolves.toEqual(undefined);
    });
  });

  describe('Scope SETTINGS', () => {
    const scope = BackgroundTaskScope.Settings;

    it('should throw an error if the user has no capa SETTINGS_SETLABELS', async () => {
      const user = userParticipate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }],
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });
  });

  describe('Scope KNOWLEDGE', () => {
    const scope = BackgroundTaskScope.Knowledge;

    it('should throw an error if the user has no capa KNOWLEDGE_UPDATE', async () => {
      const user = userParticipate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }],
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
      await expect(checkActionValidity(testContext, userUpdate, input, scope, type)).resolves.toEqual(undefined);
    });

    it('should throw an error if deletion actions and no capa KNOWLEDGE_DELETE', async () => {
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }],
      };
      await expect(async () => {
        await checkActionValidity(testContext, userUpdate, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
      await expect(checkActionValidity(testContext, userDelete, input, scope, type)).resolves.toEqual(undefined);
    });

    it('should throw an error if merge actions and no capa KNOWLEDGE_MERGE', async () => {
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_MERGE }],
      };
      await expect(async () => {
        await checkActionValidity(testContext, userUpdate, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
      await expect(checkActionValidity(testContext, userMerge, input, scope, type)).resolves.toEqual(undefined);
    });

    it('should throw an error if task QUERY and targeting vocabularies', async () => {
      const user = userUpdate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }],
        filters: filterEntityType(ENTITY_TYPE_VOCABULARY),
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('The targeted ids are not knowledge.');
    });

    it('should throw an error if task QUERY and targets are not knowledge', async () => {
      const user = userUpdate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }],
        filters: filterEntityType(ENTITY_TYPE_WORKSPACE),
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('The targeted ids are not knowledge.');
    });

    it.skip('should throw an error if task LIST and targets are not knowledge', () => {
      // TODO
    });
  });

  describe('Scope USER_NOTIFICATION', () => {
    const scope = BackgroundTaskScope.UserNotification;

    it('should throw an error if task QUERY and filter is not Notifications', async () => {
      const user = userUpdate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }],
        filters: filterEntityType(ENTITY_TYPE_WORKSPACE),
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('The targeted ids are not notifications.');
    });

    it('should throw an error if task QUERY and user has no capa SETTINGS_SET_ACCESSES and not own data', async () => {
      const user = userUpdate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }],
        filters: filterEntityType(ENTITY_TYPE_NOTIFICATION),
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
      const input2 = {
        actions: [{ type: ACTION_TYPE_ADD }],
        filters: JSON.stringify({
          mode: 'and',
          filters: [
            { key: TYPE_FILTER, values: [ENTITY_TYPE_NOTIFICATION] },
            { key: USER_ID_FILTER, values: ['fake_user_id'] },
          ],
          filterGroups: [],
        }),
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input2, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });

    it('should NOT throw an error if task QUERY and filter is Notification of the user', async () => {
      const user = userUpdate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }],
        filters: JSON.stringify({
          mode: 'and',
          filters: [
            { key: TYPE_FILTER, values: [ENTITY_TYPE_NOTIFICATION] },
            { key: USER_ID_FILTER, values: [user.id] },
          ],
          filterGroups: [],
        }),
      };
      await checkActionValidity(testContext, user, input, scope, type);
    });

    it.skip('should throw an error if task LIST and targets are not Notifications', () => {
      // TODO
    });

    it.skip('should throw an error if task LIST and user has no capa SETTINGS_SET_ACCESSES and not own data', () => {
      // TODO
    });
  });

  describe('Scope IMPORT', () => {
    const scope = BackgroundTaskScope.Import;

    it('should throw an error if the user has no capa KNOWLEDGE_KNASKIMPORT', async () => {
      const user = userParticipate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }],
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });

    it('should throw an error if some actions are not deletions', async () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }, { type: ACTION_TYPE_ADD }],
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('Background tasks of scope Import can only be deletions.');
    });
  });

  describe('Scope DASHBOARD', () => {
    const scope = BackgroundTaskScope.Dashboard;

    it('should throw an error if the user has no capa EXPLORE_EXUPDATE_EXDELETE', async () => {
      const user = userParticipate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }],
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });

    it('should throw an error if some actions are not deletions', async () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }, { type: ACTION_TYPE_ADD }],
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('Background tasks of scope dashboard can only be deletions.');
    });

    it('should throw an error if task QUERY and filter is not Workspace', async () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }],
        filters: filterEntityType(ENTITY_TYPE_NOTIFICATION),
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('The targeted ids are not dashboard.');
    });

    it('should throw an error if task QUERY and filter type is not dashboard', async () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }],
        filters: filterWorkspaceType('investigation'),
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('The targeted ids are not dashboard.');
    });

    it.skip('should throw an error if task LIST and targets are not dashboards', () => {
      // TODO
    });
  });

  describe('Scope INVESTIGATION', () => {
    const scope = BackgroundTaskScope.Investigation;

    it('should throw an error if the user has no capa KNOWLEDGE_KNGETEXPORT_KNASKEXPORT', async () => {
      const user = userParticipate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }],
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });

    it('should throw an error if some actions are not deletions', async () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }, { type: ACTION_TYPE_ADD }],
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('Background tasks of scope investigation can only be deletions.');
    });

    it('should throw an error if task QUERY and filter is not Workspace', async () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }],
        filters: filterEntityType(ENTITY_TYPE_NOTIFICATION),
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('The targeted ids are not investigations.');
    });

    it('should throw an error if task QUERY and filter type is not investigation', async () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }],
        filters: filterWorkspaceType('dashboard'),
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('The targeted ids are not investigations.');
    });

    it.skip('should throw an error if task LIST and targets are not investigations', () => {
      // TODO
    });
  });

  describe('Scope PUBLIC_DASHBOARD', () => {
    const scope = BackgroundTaskScope.PublicDashboard;

    it('should throw an error if the user has no capa EXPLORE_EXUPDATE_PUBLISH', async () => {
      const user = userParticipate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }],
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });

    it('should throw an error if some actions are not deletions', async () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }, { type: ACTION_TYPE_ADD }],
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('Background tasks of scope Public dashboard can only be deletions.');
    });

    it('should throw an error if task QUERY and filter is not PublicDashboard', async () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }],
        filters: filterEntityType(ENTITY_TYPE_NOTIFICATION),
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('The targeted ids are not public dashboards.');
    });

    it.skip('should throw an error if task QUERY and user has access to 0 public dashboard', () => {
      // TODO
    });

    it.skip('should throw an error if task LIST and targets are not public dashboards', () => {
      // TODO
    });
  });
});
