import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/domain/rules', () => ({ getRule: vi.fn(), setRuleActivation: vi.fn() }));
vi.mock('../../../../src/database/cluster-module', () => ({ isModuleActivated: vi.fn() }));

import { getRule, setRuleActivation } from '../../../../src/domain/rules';
import { isModuleActivated } from '../../../../src/database/cluster-module';
import { importConfigPresetRule, RULE_ACTIVATION_SCAN_REASON, RULE_DEACTIVATION_SCAN_REASON } from '../../../../src/modules/rule/rule-import';
import { exportConfigPresetRule } from '../../../../src/modules/rule/rule-export';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import type { RuleRuntime } from '../../../../src/types/rules';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'admin-id' } as AuthUser;
const RULE_ID = 'attribution_use';
const overwrite = { mode: ConfigImportMode.Overwrite };

const withRule = (activated: boolean | undefined) => vi.mocked(getRule).mockResolvedValue({ id: RULE_ID, name: 'Usage propagation via attribution', activated } as RuleRuntime);

describe('Rule import', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(isModuleActivated).mockResolvedValue(true);
  });

  it.each([
    [true, RULE_ACTIVATION_SCAN_REASON],
    [false, RULE_DEACTIVATION_SCAN_REASON],
  ])('switches the rule to active: %s, and warns of the scan the rule engine starts', async (active, reason) => {
    withRule(!active);
    expect(await importConfigPresetRule(context, user, RULE_ID, { active }, overwrite)).toEqual({ status: 'overwritten', exists: true, configuration: { active }, reason });
    expect(setRuleActivation).toHaveBeenCalledWith(context, user, RULE_ID, active);
    expect(isModuleActivated).toHaveBeenCalledWith('RULE_ENGINE');
  });

  it('decides the same result on a dry run, and writes nothing', async () => {
    withRule(false);
    expect(await importConfigPresetRule(context, user, RULE_ID, { active: true }, { ...overwrite, dryRun: true }))
      .toEqual({ status: 'overwritten', exists: true, configuration: { active: true }, reason: RULE_ACTIVATION_SCAN_REASON });
    expect(setRuleActivation).not.toHaveBeenCalled();
  });

  it('warns of no scan when the rule engine does not run', async () => {
    withRule(false);
    vi.mocked(isModuleActivated).mockResolvedValue(false);
    const result = await importConfigPresetRule(context, user, RULE_ID, { active: true }, overwrite);
    expect(result).toEqual({ status: 'overwritten', exists: true, configuration: { active: true } });
    expect(setRuleActivation).toHaveBeenCalledWith(context, user, RULE_ID, true);
  });

  it.each([[true, true], [false, false], [undefined, false]])('skips a rule already in the state of the bundle (stored: %s, bundle: %s), without a scan', async (activated, active) => {
    withRule(activated);
    expect(await importConfigPresetRule(context, user, RULE_ID, { active }, overwrite))
      .toEqual({ status: 'skipped', code: 'unchanged', reason: 'Already up to date', exists: true, configuration: { active } });
    expect(setRuleActivation).not.toHaveBeenCalled();
  });

  it('fails a rule this platform does not declare', async () => {
    vi.mocked(getRule).mockResolvedValue(undefined);
    expect(await importConfigPresetRule(context, user, 'unknown_rule', { active: true }, overwrite))
      .toEqual({ status: 'failed', code: 'unknown_rule', reason: 'Unknown rule', exists: false, configuration: { active: true } });
    expect(setRuleActivation).not.toHaveBeenCalled();
  });

  it.each([
    [{}, 'active: Invalid input: expected boolean, received undefined'],
    [{ active: 'yes' }, 'active: Invalid input: expected boolean, received string'],
    [{ active: true, other: 1 }, 'configuration: Unrecognized key: "other"'],
    [null, 'configuration: Invalid input: expected object, received null'],
  ])('fails an invalid configuration %j', async (configuration, reason) => {
    withRule(false);
    expect(await importConfigPresetRule(context, user, RULE_ID, configuration, overwrite)).toEqual({ status: 'failed', code: 'invalid', reason, exists: true });
    expect(setRuleActivation).not.toHaveBeenCalled();
  });

  it.each([ConfigImportMode.Add, ConfigImportMode.Copy])('leaves the rule as it is with the mode %s: a rule has no copy', async (mode) => {
    withRule(false);
    expect(await importConfigPresetRule(context, user, RULE_ID, { active: true }, { mode }))
      .toEqual({ status: 'skipped', code: 'not_overwrite', reason: 'Already exists', exists: true, configuration: { active: true } });
    expect(setRuleActivation).not.toHaveBeenCalled();
  });

  it('exports the activation as the import takes it back', () => {
    expect(exportConfigPresetRule({ activated: true })).toEqual({ active: true });
    expect(exportConfigPresetRule({ activated: false })).toEqual({ active: false });
    expect(exportConfigPresetRule({})).toEqual({ active: false });
  });
});
