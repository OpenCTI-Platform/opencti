import { describe, expect, it } from 'vitest';
import LocationTargetsRule from '../../src/rules/location-targets/LocationTargetsRule';
import { getRule } from '../../src/domain/rules';
import { importConfigPresetRule, RULE_ACTIVATION_SCAN_REASON, RULE_DEACTIVATION_SCAN_REASON } from '../../src/modules/rule/rule-import';
import { ConfigImportMode } from '../../src/modules/configImport/configImport-types';
import { internalFindByIds, topEntitiesList } from '../../src/database/middleware-loader';
import { isNotEmptyField, READ_INDEX_HISTORY } from '../../src/database/utils';
import { ENTITY_TYPE_BACKGROUND_TASK } from '../../src/schema/internalObject';
import { TASK_TYPE_RULE } from '../../src/domain/backgroundTask-common';
import { fetchStreamInfo } from '../../src/database/stream/stream-handler';
import { getManagerInfo } from '../../src/manager/ruleManager';
import { SYSTEM_USER } from '../../src/utils/access';
import { ADMIN_USER, FIVE_MINUTES, testContext } from '../utils/testQuery';
import { awaitUntilCondition } from '../utils/testQueryHelper';

const RULE_ID = LocationTargetsRule.id;
const overwrite = { mode: ConfigImportMode.Overwrite };
const isActivated = async () => (await getRule(testContext, ADMIN_USER, RULE_ID))?.activated === true;

interface RuleTask {
  type: string;
  rule: string;
  enable: boolean;
  completed: boolean;
  errors: unknown[];
  work_id?: string;
}

// The same wait as changeRule (rule-utils), after a switch made by the import instead of the mutation:
// the rule task is done without error, then the rule manager has caught up with the stream
const awaitRuleTask = async (active: boolean) => {
  await awaitUntilCondition(async () => {
    const tasks = (await topEntitiesList(testContext, SYSTEM_USER, [ENTITY_TYPE_BACKGROUND_TASK])) as unknown as RuleTask[];
    const ruleTasks = tasks.filter((task) => task.type === TASK_TYPE_RULE && task.rule === RULE_ID && task.enable === active);
    ruleTasks.forEach((task) => expect(task.errors.length).toBe(0));
    const workIds = ruleTasks.map((task) => task.work_id).filter((workId): workId is string => isNotEmptyField(workId));
    const works = (await internalFindByIds(testContext, SYSTEM_USER, workIds, { indices: [READ_INDEX_HISTORY] })) as unknown as { status: string; errors: unknown[] }[];
    works.forEach((work) => expect(work.errors.length).toBe(0));
    return ruleTasks.every((task) => task.completed) && works.every((work) => work.status === 'complete');
  }, 10000, { intervalMs: 1000, message: `Rule ${RULE_ID} did not finish its task` });
  let stableCount = 1;
  await awaitUntilCondition(async () => {
    const streamInfo = await fetchStreamInfo();
    const managerInfo = await getManagerInfo(testContext, SYSTEM_USER);
    const eventDate = (eventId?: string | null) => new Date(parseInt(eventId?.split('-').at(0) ?? '0', 10));
    const lastEventDate = eventDate(streamInfo.lastEventId);
    const managerEventDate = eventDate(managerInfo.lastEventId);
    if (managerEventDate >= lastEventDate) {
      stableCount += 1;
    }
    return stableCount >= 3;
  }, 15000, { intervalMs: 2000, message: `Rule ${RULE_ID} stream did not stabilise` });
};

describe('Config preset import of a rule', () => {
  it('switches the rule on then off through its rule task, then finds it up to date', async () => {
    expect(await isActivated()).toBe(false);

    expect(await importConfigPresetRule(testContext, ADMIN_USER, RULE_ID, { active: true }, overwrite))
      .toEqual({ status: 'overwritten', exists: true, configuration: { active: true }, reason: RULE_ACTIVATION_SCAN_REASON });
    await awaitRuleTask(true);
    expect(await isActivated()).toBe(true);
    expect(await importConfigPresetRule(testContext, ADMIN_USER, RULE_ID, { active: true }, overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged' });

    expect(await importConfigPresetRule(testContext, ADMIN_USER, RULE_ID, { active: false }, overwrite))
      .toEqual({ status: 'overwritten', exists: true, configuration: { active: false }, reason: RULE_DEACTIVATION_SCAN_REASON });
    await awaitRuleTask(false);
    expect(await isActivated()).toBe(false);
  }, FIVE_MINUTES);
});
