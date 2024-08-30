import { describe, expect, it } from 'vitest';
import { ACTION_TYPE_DELETE, checkActionValidity, TASK_TYPE_QUERY } from '../../../src/domain/backgroundTask-common';
import { buildStandardUser, testContext } from '../../utils/testQuery';
import { ACTION_TYPE_ADD } from '../../../src/domain/backgroundTask';
import { ENTITY_TYPE_VOCABULARY } from '../../../src/modules/vocabulary/vocabulary-types';
import { ENTITY_TYPE_WORKSPACE } from '../../../src/modules/workspace/workspace-types';
import { ENTITY_TYPE_NOTIFICATION } from '../../../src/modules/notification/notification-types';

const filterEntityType = (entityType: string) => {
  return JSON.stringify({
    mode: 'and',
    filters: [
      {
        key: ['entity_type'],
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
        key: ['entity_type'],
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
    const scope = 'SETTINGS';

    it('should throw an error if the user has no capa SETTINGS_SETLABELS', () => {
      const user = userParticipate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }]
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });
  });

  describe('Scope KNOWLEDGE', () => {
    const scope = 'KNOWLEDGE';

    it('should throw an error if the user has no capa KNOWLEDGE_UPDATE', () => {
      const user = userParticipate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }]
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });

    it('should throw an error if deletion actions and no capa KNOWLEDGE_DELETE', () => {
      const user = userUpdate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }]
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });

    it('should throw an error if task QUERY and targeting vocabularies', () => {
      const user = userUpdate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }],
        filters: filterEntityType(ENTITY_TYPE_VOCABULARY)
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('The targeted ids are not knowledge.');
    });

    it('should throw an error if task QUERY and targets are not knowledge', () => {
      const user = userUpdate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }],
        filters: filterEntityType(ENTITY_TYPE_WORKSPACE)
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('The targeted ids are not knowledge.');
    });

    it.skip('should throw an error if task LIST and targets are not knowledge', () => {
      // TODO
    });
  });

  describe('Scope USER', () => {
    const scope = 'USER';

    it('should throw an error if task QUERY and filter is not Notifications', () => {
      const user = userUpdate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }],
        filters: filterEntityType(ENTITY_TYPE_WORKSPACE)
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('The targeted ids are not notifications.');
    });

    it('should throw an error if task QUERY and user has no capa SETTINGS_SET_ACCESSES and not own data', () => {
      const user = userUpdate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }],
        filters: filterEntityType(ENTITY_TYPE_NOTIFICATION)
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });

    it.skip('should throw an error if task LIST and targets are not Notifications', () => {
      // TODO
    });

    it.skip('should throw an error if task LIST and user has no capa SETTINGS_SET_ACCESSES and not own data', () => {
      // TODO
    });
  });

  describe('Scope IMPORT', () => {
    const scope = 'IMPORT';

    it('should throw an error if the user has no capa KNOWLEDGE_KNASKIMPORT', () => {
      const user = userParticipate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }]
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });

    it('should throw an error if some actions are not deletions', () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }, { type: ACTION_TYPE_ADD }]
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('Background tasks of scope Import can only be deletions.');
    });
  });

  describe('Scope DASHBOARD', () => {
    const scope = 'DASHBOARD';

    it('should throw an error if the user has no capa EXPLORE_EXUPDATE_EXDELETE', () => {
      const user = userParticipate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }]
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });

    it('should throw an error if some actions are not deletions', () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }, { type: ACTION_TYPE_ADD }]
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('Background tasks of scope dashboard can only be deletions.');
    });

    it('should throw an error if task QUERY and filter is not Workspace', () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }],
        filters: filterEntityType(ENTITY_TYPE_NOTIFICATION)
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('The targeted ids are not dashboard.');
    });

    it('should throw an error if task QUERY and filter type is not dashboard', () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }],
        filters: filterWorkspaceType('investigation')
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('The targeted ids are not dashboard.');
    });

    it.skip('should throw an error if task LIST and targets are not dashboards', () => {
      // TODO
    });
  });

  describe('Scope INVESTIGATION', () => {
    const scope = 'INVESTIGATION';

    it('should throw an error if the user has no capa KNOWLEDGE_KNGETEXPORT_KNASKEXPORT', () => {
      const user = userParticipate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }]
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });

    it('should throw an error if some actions are not deletions', () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }, { type: ACTION_TYPE_ADD }]
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('Background tasks of scope investigation can only be deletions.');
    });

    it('should throw an error if task QUERY and filter is not Workspace', () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }],
        filters: filterEntityType(ENTITY_TYPE_NOTIFICATION)
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('The targeted ids are not investigations.');
    });

    it('should throw an error if task QUERY and filter type is not investigation', () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }],
        filters: filterWorkspaceType('dashboard')
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('The targeted ids are not investigations.');
    });

    it.skip('should throw an error if task LIST and targets are not investigations', () => {
      // TODO
    });
  });

  describe('Scope PUBLIC_DASHBOARD', () => {
    const scope = 'PUBLIC_DASHBOARD';

    it('should throw an error if the user has no capa EXPLORE_EXUPDATE_PUBLISH', () => {
      const user = userParticipate;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_ADD }]
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('You are not allowed to do this.');
    });

    it('should throw an error if some actions are not deletions', () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }, { type: ACTION_TYPE_ADD }]
      };
      expect(async () => {
        await checkActionValidity(testContext, user, input, scope, type);
      }).rejects.toThrowError('Background tasks of scope Public dashboard can only be deletions.');
    });

    it('should throw an error if task QUERY and filter is not PublicDashboard', () => {
      const user = userEditor;
      const type = TASK_TYPE_QUERY;
      const input = {
        actions: [{ type: ACTION_TYPE_DELETE }],
        filters: filterEntityType(ENTITY_TYPE_NOTIFICATION)
      };
      expect(async () => {
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
