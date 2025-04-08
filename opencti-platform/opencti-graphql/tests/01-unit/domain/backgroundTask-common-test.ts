import { describe, expect, it } from 'vitest';
import { ACTION_TYPE_DELETE, checkActionValidity, TASK_TYPE_QUERY } from '../../../src/domain/backgroundTask-common';
import { buildStandardUser, testContext } from '../../utils/testQuery';
import { ACTION_TYPE_ADD } from '../../../src/domain/backgroundTask';
import { ENTITY_TYPE_VOCABULARY } from '../../../src/modules/vocabulary/vocabulary-types';
import { ENTITY_TYPE_WORKSPACE } from '../../../src/modules/workspace/workspace-types';
import { ENTITY_TYPE_NOTIFICATION } from '../../../src/modules/notification/notification-types';
import { TYPE_FILTER, USER_ID_FILTER } from '../../../src/utils/filtering/filtering-constants';
import { BackgroundTaskScope } from '../../../src/generated/graphql';

const filterEntityType = (entityType: string) => {
  return JSON.stringify({
    mode: 'and',
    filters: [
      {
        key: [TYPE_FILTER],
        values: [entityType],
        operator: 'eq',
        mode: 'or'
      }
    ],
    filterGroups: []
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
        mode: 'or'
      },
      {
        key: ['type'],
        values: [type],
        operator: 'eq',
        mode: 'or'
      }
    ],
    filterGroups: []
  });
};

describe('Background task validity check (checkActionValidity)', () => {
  const userParticipate = buildStandardUser([], [], [{ name: 'KNOWLEDGE_KNPARTICIPATE' }]);
  const userUpdate = buildStandardUser([], [], [{ name: 'KNOWLEDGE_KNUPDATE' }]);
  const userEditor = buildStandardUser([], [], [
    { name: 'KNOWLEDGE_KNUPDATE_KNDELETE' },
    { name: 'KNOWLEDGE_KNASKIMPORT' },
    { name: 'EXPLORE_EXUPDATE_EXDELETE' },
    { name: 'EXPLORE_EXUPDATE_PUBLISH' },
    { name: 'INVESTIGATION_INUPDATE_INDELETE' },
  ]);

  describe('Scope SETTINGS', () => {
    const scope = BackgroundTaskScope.Settings;

    it('should throw an error if the user has no capa SETTINGS_SETLABELS', async () => {
      const user = userParticipate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }]
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
        actions: [{ type: ACTION_TYPE_ADD }]
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });

    it('should throw an error if deletion actions and no capa KNOWLEDGE_DELETE', async () => {
      const user = userUpdate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }]
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });

    it('should throw an error if task QUERY and targeting vocabularies', async () => {
      const user = userUpdate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }],
        filters: filterEntityType(ENTITY_TYPE_VOCABULARY)
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
        filters: filterEntityType(ENTITY_TYPE_WORKSPACE)
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('The targeted ids are not knowledge.');
    });

    it.skip('should throw an error if task LIST and targets are not knowledge', () => {
      // TODO
    });
  });

  describe('Scope USER', () => {
    const scope = BackgroundTaskScope.User;

    it('should throw an error if task QUERY and filter is not Notifications', async () => {
      const user = userUpdate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }],
        filters: filterEntityType(ENTITY_TYPE_WORKSPACE)
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
        filters: filterEntityType(ENTITY_TYPE_NOTIFICATION)
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
          filterGroups: []
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
          filterGroups: []
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
        actions: [{ type: ACTION_TYPE_ADD }]
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });

    it('should throw an error if some actions are not deletions', async () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }, { type: ACTION_TYPE_ADD }]
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
        actions: [{ type: ACTION_TYPE_ADD }]
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });

    it('should throw an error if some actions are not deletions', async () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }, { type: ACTION_TYPE_ADD }]
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
        filters: filterEntityType(ENTITY_TYPE_NOTIFICATION)
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
        filters: filterWorkspaceType('investigation')
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
        actions: [{ type: ACTION_TYPE_ADD }]
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });

    it('should throw an error if some actions are not deletions', async () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }, { type: ACTION_TYPE_ADD }]
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
        filters: filterEntityType(ENTITY_TYPE_NOTIFICATION)
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
        filters: filterWorkspaceType('dashboard')
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
        actions: [{ type: ACTION_TYPE_ADD }]
      };
      await expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });

    it('should throw an error if some actions are not deletions', async () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }, { type: ACTION_TYPE_ADD }]
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
        filters: filterEntityType(ENTITY_TYPE_NOTIFICATION)
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
