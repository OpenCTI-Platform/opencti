import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { UserMergeHandlerPlan } from '../../../../src/modules/userMerge/userMerge-handler';
import { USER_MERGE_FILTER_TARGETS, type UserMergeFilterTarget } from '../../../../src/modules/userMerge/userMerge-filterTargets';

const elRawSearch = vi.fn();
const elBulk = vi.fn();
vi.mock('../../../../src/database/engine', () => ({
  elRawUpdateByQuery: async () => ({}),
  elRawSearch: (context: unknown, user: unknown, scope: unknown, args: unknown) => elRawSearch(context, user, scope, args),
  elBulk: (context: unknown, args: unknown) => elBulk(context, args),
}));

const { USER_MERGE_FILTERS_HANDLER, userMergeFiltersHandler } = await import('../../../../src/modules/userMerge/userMerge-filtersHandler');

const SOURCE = 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa';
const TARGET = 'bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb';
const OTHER = 'cccccccc-3333-4333-8333-cccccccccccc';

const filterGroup = (values: unknown[], key = 'creator_id') => JSON.stringify({
  mode: 'and',
  filters: [{ key: [key], values, operator: 'eq', mode: 'or' }],
  filterGroups: [],
});

const targetNamed = (id: string): UserMergeFilterTarget => USER_MERGE_FILTER_TARGETS.find((entry) => entry.id === id)!;

/**
 * What the scan is asked for, expressed the way the handler asks for it: an entity type, and for
 * a plain field the path it pre-selects on. Two targets can share an entity type, so the path is
 * what tells them apart.
 */
const scanKey = (query: any): string => {
  const must = query.bool.must;
  const entityType = must[0].terms['entity_type.keyword'][0];
  const phrase = must[1]?.match_phrase;
  return phrase ? `${entityType}:${Object.keys(phrase)[0]}` : entityType;
};

const staged = new Map<string, Record<string, any>[]>();

const stage = (target: UserMergeFilterTarget, sources: Record<string, any>[]) => {
  const key = target.shape === 'field' ? `${target.entityType}:${target.path}` : target.entityType;
  staged.set(key, sources);
};

const handlerContext = {
  context: {},
  sourceId: SOURCE,
  targetId: TARGET,
  sourceUser: { id: SOURCE },
  targetUser: { id: TARGET },
} as never;

const alertsAbout = (alerts: { message: string }[], fragment: string) => alerts.filter((alert) => alert.message.includes(fragment));

const changeFor = (plan: UserMergeHandlerPlan, rowId: string) => plan.changes.find((change) => change.register_row_id === rowId)!;

describe('userMerge filters handler', () => {
  beforeEach(() => {
    staged.clear();
    elRawSearch.mockReset();
    elBulk.mockReset();
    elBulk.mockResolvedValue({});
    elRawSearch.mockImplementation((_c: unknown, _u: unknown, _s: unknown, args: any) => {
      const sources = staged.get(scanKey(args.body.query)) ?? [];
      return Promise.resolve({
        hits: { hits: sources.map((source, index) => ({ _id: `doc-${index}`, _index: 'opencti_internal_objects', _source: source, sort: [`doc-${index}`] })) },
      });
    });
  });

  describe('Plan', () => {
    it('should count the documents it rewrites and name the field it rewrites them in', async () => {
      const trigger = targetNamed('trigger-filters');
      stage(trigger, [{ filters: filterGroup([SOURCE]) }, { filters: filterGroup([OTHER, SOURCE]) }]);
      const plan = await userMergeFiltersHandler.compute(handlerContext);
      expect(plan.handler).toEqual(USER_MERGE_FILTERS_HANDLER);
      expect(changeFor(plan, trigger.registerRow)).toMatchObject({ entity_type: trigger.entityType, count: 2, exact: true, detail: 'filters' });
      expect(plan.alerts).toEqual([]);
    });

    it('should leave a document that carries no reference to the source out of the count', async () => {
      const trigger = targetNamed('trigger-filters');
      stage(trigger, [{ filters: filterGroup([OTHER]) }, { name: 'no filters at all' }]);
      const plan = await userMergeFiltersHandler.compute(handlerContext);
      expect(changeFor(plan, trigger.registerRow).count).toEqual(0);
      expect(plan.alerts).toEqual([]);
    });

    // The two call for opposite follow-ups, so they are never summed into one number.
    it('should report an unreadable filter apart from one mentioning the id as free text', async () => {
      const trigger = targetNamed('trigger-filters');
      stage(trigger, [{ filters: `{ broken ${SOURCE}` }, { filters: filterGroup([`created by ${SOURCE}`], 'name') }]);
      const plan = await userMergeFiltersHandler.compute(handlerContext);
      expect(changeFor(plan, trigger.registerRow).count).toEqual(0);
      expect(alertsAbout(plan.alerts, 'cannot parse')).toHaveLength(1);
      expect(alertsAbout(plan.alerts, 'rather than as one')).toHaveLength(1);
    });

    // The precondition is an idle platform; a live entity is reported rather than orchestrated.
    it('should report an entity that was live while the platform was expected to be at rest', async () => {
      const task = targetNamed('background-task-filters');
      const connector = targetNamed('connector-trigger-filters');
      stage(task, [{ task_filters: filterGroup([SOURCE]), completed: false }]);
      stage(connector, [{ connector_trigger_filters: filterGroup([SOURCE]), active: true }]);
      const plan = await userMergeFiltersHandler.compute(handlerContext);
      expect(alertsAbout(plan.alerts, 'at rest')).toHaveLength(2);
    });

    it('should stay silent on an entity whose lifecycle state the precondition allows', async () => {
      const task = targetNamed('background-task-filters');
      const connector = targetNamed('connector-trigger-filters');
      stage(task, [{ task_filters: filterGroup([SOURCE]), completed: true }]);
      stage(connector, [{ connector_trigger_filters: filterGroup([SOURCE]), active: false }]);
      const plan = await userMergeFiltersHandler.compute(handlerContext);
      expect(alertsAbout(plan.alerts, 'at rest')).toHaveLength(0);
    });

    // computePirScore divides by the sum of every criterion weight, so a fold changes the scale
    // of every score of that PIR: the operator has to know.
    it('should report the PIR criteria a remap folded into one', async () => {
      const pir = targetNamed('pir-criteria-filters');
      stage(pir, [{ pir_criteria: [{ filters: filterGroup([SOURCE]), weight: 2 }, { filters: filterGroup([TARGET]), weight: 5 }] }]);
      const plan = await userMergeFiltersHandler.compute(handlerContext);
      expect(alertsAbout(plan.alerts, 'folded into one')).toHaveLength(1);
    });

    it('should leave a PIR whose criteria are not a list alone', async () => {
      const pir = targetNamed('pir-criteria-filters');
      stage(pir, [{ pir_criteria: 'not a list' }]);
      const plan = await userMergeFiltersHandler.compute(handlerContext);
      expect(changeFor(plan, pir.registerRow).count).toEqual(0);
      expect(plan.alerts).toEqual([]);
    });
  });

  describe('Write', () => {
    it('should write the rewritten field back, in the index the document was read from', async () => {
      const trigger = targetNamed('trigger-filters');
      stage(trigger, [{ filters: filterGroup([SOURCE]) }]);
      const plan = await userMergeFiltersHandler.compute(handlerContext);
      expect(await userMergeFiltersHandler.apply(handlerContext, plan)).toEqual(1);
      expect(elBulk).toHaveBeenCalledTimes(1);
      expect(elBulk.mock.calls[0][1].body).toEqual([
        { update: { _index: 'opencti_internal_objects', _id: 'doc-0' } },
        { doc: { filters: filterGroup([TARGET]) } },
      ]);
    });

    // The plan is what the operator validated: a target it counted at zero is not re-opened,
    // whatever the platform holds by the time the write runs.
    it('should not touch a target the plan counted at zero', async () => {
      const trigger = targetNamed('trigger-filters');
      stage(trigger, [{ filters: filterGroup([SOURCE]) }]);
      const empty = { handler: USER_MERGE_FILTERS_HANDLER, changes: [], alerts: [] };
      expect(await userMergeFiltersHandler.apply(handlerContext, empty)).toEqual(0);
      expect(elBulk).not.toHaveBeenCalled();
    });
  });
});
