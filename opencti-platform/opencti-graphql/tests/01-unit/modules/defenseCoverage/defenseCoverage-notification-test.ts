import { describe, expect, it } from 'vitest';
import {
  buildDefenseLevelMessage,
  collectDefenseCoverageChanges,
  DEFENSE_TRIGGER_LEVEL_DECREASED,
  DEFENSE_TRIGGER_LEVEL_INCREASED,
  defenseLevelEventType,
  defensePlatformPredicate,
  notifyDefenseLevelChanges,
  readerLevelChange,
  reconcileQueuedChanges,
  triggerCoverageChange,
} from '../../../../src/modules/defenseCoverage/defenseCoverage-notification';
import { mergeQueuedLevelChange } from '../../../../src/modules/defenseCoverage/defenseCoverage-state';
import type { DefenseCoverage } from '../../../../src/modules/defenseCoverage/defenseCoverage-types';
import type { StixObject } from '../../../../src/types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import type { AuthContext } from '../../../../src/types/user';

const coverage = (level: number, computedAt: string | null = '2026-10-01T00:00:00.000Z') => {
  return { computed_at: computedAt ?? undefined, level, data_components: [], rules: [], mitigations: [], validations: [], platforms: [] } as unknown as DefenseCoverage;
};

const withRules = (ruleIds: string[]) => ({ ...coverage(ruleIds.length > 0 ? 2 : 0), rules: ruleIds.map((id) => ({ id, rel: `${id}-indicates` })) });

const validated = (platformId: string, ruleId: string) => ({
  ...coverage(4),
  rules: [{ id: ruleId, rel: `${ruleId}-indicates` }],
  platforms: [{
    platform_id: platformId,
    level: 4,
    telemetry: [],
    deployments: [{ id: ruleId, rel: `${ruleId}-deployed-on`, status: 'active', indicates: `${ruleId}-indicates` }],
    validations: [{ id: 'result', rel: 'result-has-covered', status: 'detected', last_result_at: '2026-10-02T00:00:00.000Z', scores: [] }],
  }],
}) as DefenseCoverage;

const only = (ids: string[]) => (id: string | undefined) => !!id && ids.includes(id);

describe('Defense level notifications', () => {
  it('should keep every coverage change of an already computed technique', () => {
    const changes = collectDefenseCoverageChanges([
      { attackPatternId: 'decreased', previous: coverage(3), coverage: coverage(1) },
      { attackPatternId: 'same level, other evidences', previous: coverage(2), coverage: coverage(2) },
      { attackPatternId: 'first computation', previous: undefined, coverage: coverage(3) },
      { attackPatternId: 'never computed', previous: coverage(1, null), coverage: coverage(3) },
    ]);
    expect(changes.map((change) => change.attack_pattern_id)).toEqual(['decreased', 'same level, other evidences']);
    expect(changes[0].previous.level).toEqual(3);
    expect(changes[0].coverage.level).toEqual(1);
  });

  it('should tell a queued change only up to the coverage actually stored', () => {
    const queued = [
      { attack_pattern_id: 'stored', previous: withRules([]), coverage: withRules(['rule']), delivered_trigger_ids: ['trigger-1'] },
      { attack_pattern_id: 'storage failed', previous: withRules([]), coverage: withRules(['rule']) },
      { attack_pattern_id: 'revoked', previous: withRules([]), coverage: withRules(['rule']) },
    ];
    const stored = new Map([['stored', withRules(['rule'])], ['storage failed', withRules([])]]);
    const { changes, dropped } = reconcileQueuedChanges(queued, stored);
    expect(dropped).toEqual(['revoked']);
    expect(changes.map((change) => change.attack_pattern_id)).toEqual(['stored', 'storage failed']);
    expect(changes[0].delivered_trigger_ids).toEqual(['trigger-1']);
    const visible = only(['rule', 'rule-indicates']);
    expect(readerLevelChange(changes[0], visible)).toEqual({ attack_pattern_id: 'stored', previous_level: 0, level: 2 });
    // The coverage was never stored: the technique is back at its previous level and nobody is told a change
    expect(readerLevelChange(changes[1], visible)).toBeUndefined();
  });

  it('should tell the triggers a failed delivery reached the change from the coverage they were told', () => {
    // trigger-a was told that the rule appeared, the delivery failed before trigger-b, then the rule was removed
    const earlier = { attack_pattern_id: 'ap', previous: withRules([]), coverage: withRules(['rule']), delivered_trigger_ids: ['trigger-a'] };
    const queued = mergeQueuedLevelChange(earlier, { attack_pattern_id: 'ap', previous: withRules(['rule']), coverage: withRules([]) });
    const { changes } = reconcileQueuedChanges([queued], new Map([['ap', withRules([])]]));
    const visible = only(['rule', 'rule-indicates']);
    expect(readerLevelChange(triggerCoverageChange(changes[0], 'trigger-a'), visible)).toEqual({ attack_pattern_id: 'ap', previous_level: 2, level: 0 });
    // trigger-b was never told that the rule appeared: the technique is back where it was for it
    expect(readerLevelChange(triggerCoverageChange(changes[0], 'trigger-b'), visible)).toBeUndefined();
  });

  it('should compute the change with the evidences the recipient can access', () => {
    const change = { attack_pattern_id: 'ap', previous: withRules([]), coverage: withRules(['restricted']) };
    expect(readerLevelChange(change, only(['restricted', 'restricted-indicates']))).toEqual({ attack_pattern_id: 'ap', previous_level: 0, level: 2 });
    // The aggregate level rose only because of a rule the recipient cannot see
    expect(readerLevelChange(change, only([]))).toBeUndefined();
  });

  it('should report a change the recipient sees even when the aggregate level is unchanged', () => {
    const change = { attack_pattern_id: 'ap', previous: withRules(['restricted']), coverage: withRules(['restricted', 'visible']) };
    expect(change.previous.level).toEqual(change.coverage.level);
    expect(readerLevelChange(change, only(['visible', 'visible-indicates']))).toEqual({ attack_pattern_id: 'ap', previous_level: 0, level: 2 });
  });

  it('should never reveal a validation the recipient cannot access', () => {
    const change = { attack_pattern_id: 'ap', previous: validated('edr', 'rule'), coverage: withRules(['rule']) };
    const ruleAccess = ['edr', 'rule', 'rule-indicates', 'rule-deployed-on'];
    // Without access to the result, the recipient saw a deployed detection and now sees an available one
    expect(readerLevelChange(change, only(ruleAccess))).toEqual({ attack_pattern_id: 'ap', previous_level: 3, level: 2 });
    expect(readerLevelChange(change, only([...ruleAccess, 'result', 'result-has-covered']))).toEqual({ attack_pattern_id: 'ap', previous_level: 4, level: 2 });
  });

  it('should count a System only when the recipient can access one of its provides relationships', () => {
    const providesBySystem = new Map([['system', ['system-provides-1', 'system-provides-2']]]);
    const access = ['system', 'rule', 'rule-indicates', 'rule-deployed-on', 'result', 'result-has-covered'];
    const change = { attack_pattern_id: 'ap', previous: validated('system', 'rule'), coverage: withRules(['rule']) };
    const withProvides = only([...access, 'system-provides-2']);
    expect(defensePlatformPredicate(providesBySystem, withProvides)('system')).toEqual(true);
    expect(readerLevelChange(change, withProvides, defensePlatformPredicate(providesBySystem, withProvides))).toEqual({ attack_pattern_id: 'ap', previous_level: 4, level: 2 });
    // The System is not a defense platform for this recipient: its validation never counted for them
    const withoutProvides = only(access);
    expect(defensePlatformPredicate(providesBySystem, withoutProvides)('system')).toEqual(false);
    expect(readerLevelChange(change, withoutProvides, defensePlatformPredicate(providesBySystem, withoutProvides))).toBeUndefined();
    // A platform without provides relationships relies on the access to the platform itself
    expect(defensePlatformPredicate(providesBySystem, withoutProvides)('edr')).toEqual(true);
  });

  it('should map the direction of a change to its trigger event type', () => {
    expect(defenseLevelEventType({ attack_pattern_id: 'ap', previous_level: 4, level: 0 })).toEqual(DEFENSE_TRIGGER_LEVEL_DECREASED);
    expect(defenseLevelEventType({ attack_pattern_id: 'ap', previous_level: 0, level: 1 })).toEqual(DEFENSE_TRIGGER_LEVEL_INCREASED);
    expect(DEFENSE_TRIGGER_LEVEL_DECREASED).toEqual('defense_level_decreased');
    expect(DEFENSE_TRIGGER_LEVEL_INCREASED).toEqual('defense_level_increased');
  });

  it('should describe the change with both levels and their meaning', () => {
    const stix = { type: 'attack-pattern', name: 'Command and Scripting Interpreter', extensions: { [STIX_EXT_OCTI]: { type: 'Attack-Pattern' } } } as unknown as StixObject;
    expect(buildDefenseLevelMessage(stix, { attack_pattern_id: 'ap', previous_level: 3, level: 1 }))
      .toEqual('[defense] `Command and Scripting Interpreter`: defense level decreased from 3 (detection deployed) to 1 (telemetry)');
    expect(buildDefenseLevelMessage(stix, { attack_pattern_id: 'ap', previous_level: 2, level: 4 }))
      .toEqual('[defense] `Command and Scripting Interpreter`: defense level increased from 2 (detection available) to 4 (validated)');
  });

  it('should not look for triggers when nothing changed', async () => {
    await expect(notifyDefenseLevelChanges({} as AuthContext, [])).resolves.toEqual(0);
  });
});
