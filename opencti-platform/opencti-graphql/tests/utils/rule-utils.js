import { expect } from 'vitest';
import { listThings } from '../../src/database/middleware';
import { SYSTEM_USER } from '../../src/utils/access';
import { READ_INDEX_INFERRED_ENTITIES, READ_INDEX_INFERRED_RELATIONSHIPS, wait } from '../../src/database/utils';
import { ENTITY_TYPE_TASK } from '../../src/schema/internalObject';
import { setRuleActivation } from '../../src/domain/rules';
import { internalLoadById, listEntities } from '../../src/database/middleware-loader';
import { testContext } from './testQuery';
import { fetchStreamInfo } from '../../src/database/redis';
import { logApp } from '../../src/config/conf';

export const inferenceLookup = async (inferences, fromStandardId, toStandardId, type) => {
  for (let index = 0; index < inferences.length; index += 1) {
    const inference = inferences[index];
    const from = await internalLoadById(testContext, SYSTEM_USER, inference.fromId);
    const to = await internalLoadById(testContext, SYSTEM_USER, inference.toId);
    const sameFrom = from.standard_id === fromStandardId;
    const sameTo = to.standard_id === toStandardId;
    const sameType = inference.relationship_type === type;
    if (sameFrom && sameTo && sameType) {
      return inference;
    }
  }
  return null;
};

export const getInferences = (type) => {
  const opts = { indices: [READ_INDEX_INFERRED_RELATIONSHIPS, READ_INDEX_INFERRED_ENTITIES], connectionFormat: false };
  return listThings(testContext, SYSTEM_USER, [type], opts);
};

export const changeRule = async (ruleId, active) => {
  const start = new Date().getTime();
  // Change the status
  await setRuleActivation(testContext, SYSTEM_USER, ruleId, active);
  // Wait for rule to finish activation
  let ruleActivated = false;
  while (ruleActivated !== true) {
    const tasks = await listEntities(testContext, SYSTEM_USER, [ENTITY_TYPE_TASK], { connectionFormat: false });
    const allDone = tasks.filter((t) => !t.completed).length === 0;
    tasks.forEach((t) => {
      expect(t.errors.length).toBe(0);
    });
    ruleActivated = allDone;
    await wait(1000);
  }
  // Wait all events to be consumed
  let stableCount = 1;
  while (stableCount < 4) {
    const innerInfo = await fetchStreamInfo();
    const ruleManager = await internalLoadById(testContext, SYSTEM_USER, 'rule_engine_settings');
    await wait(2000);
    const lastEventDate = new Date(parseInt(innerInfo.lastEventId.split('-').at(0), 10));
    const managerEventDate = new Date(parseInt(ruleManager.lastEventId.split('-').at(0), 10));
    if (managerEventDate >= lastEventDate) {
      stableCount += 1;
    }
  }
  const stop = new Date().getTime() - start;
  logApp.info(`[TEST] Rule ${active ? ' activated' : 'disabled'} in ${stop} ms`);
};

export const activateRule = async (ruleId) => changeRule(ruleId, true);
export const disableRule = (ruleId) => changeRule(ruleId, false);
