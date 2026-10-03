import { describe, expect, it } from 'vitest';
import {
  buildDefenseLevelMessage,
  collectDefenseLevelChanges,
  DEFENSE_TRIGGER_LEVEL_DECREASED,
  DEFENSE_TRIGGER_LEVEL_INCREASED,
  defenseLevelEventType,
  notifyDefenseLevelChanges,
} from '../../../../src/modules/defenseCoverage/defenseCoverage-notification';
import type { DefenseCoverage } from '../../../../src/modules/defenseCoverage/defenseCoverage-types';
import type { StixObject } from '../../../../src/types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import type { AuthContext } from '../../../../src/types/user';

const coverage = (level: number, computedAt: string | null = '2026-10-01T00:00:00.000Z') => {
  return { computed_at: computedAt ?? undefined, level, data_components: [], rules: [], mitigations: [], validations: [], platforms: [] } as unknown as DefenseCoverage;
};

describe('Defense level notifications', () => {
  it('should only report changes of an already computed aggregate level', () => {
    const changes = collectDefenseLevelChanges([
      { attackPatternId: 'decreased', previous: coverage(3), coverage: coverage(1) },
      { attackPatternId: 'increased', previous: coverage(2), coverage: coverage(4) },
      { attackPatternId: 'same level, other evidences', previous: coverage(2), coverage: coverage(2) },
      { attackPatternId: 'first computation', previous: undefined, coverage: coverage(3) },
      { attackPatternId: 'never computed', previous: coverage(1, null), coverage: coverage(3) },
    ]);
    expect(changes).toEqual([
      { attack_pattern_id: 'decreased', previous_level: 3, level: 1 },
      { attack_pattern_id: 'increased', previous_level: 2, level: 4 },
    ]);
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
