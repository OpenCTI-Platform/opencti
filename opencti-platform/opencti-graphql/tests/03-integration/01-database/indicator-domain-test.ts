import { afterAll, describe, it, expect, vi, type MockInstance, beforeEach, afterEach } from 'vitest';
import moment from 'moment/moment';
import {
  addIndicator,
  computeIndicatorDecayHistory,
  computeIndicatorDecayPatch,
  computeLivePoints,
  computeLiveScore,
  findById,
  indicatorEditField,
  MAX_DECAY_HISTORY_POINTS,
  NO_DECAY_DEFAULT_REVOKED_SCORE,
  NO_DECAY_DEFAULT_VALID_PERIOD,
} from '../../../src/modules/indicator/indicator-domain';
import type { EditInput, IndicatorAddInput } from '../../../src/generated/graphql';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { type BasicStoreEntityIndicator, ENTITY_TYPE_INDICATOR, type IndicatorDecayRule } from '../../../src/modules/indicator/indicator-types';
import { STIX_PATTERN_TYPE } from '../../../src/utils/syntax';
import { VALID_FROM, VALID_UNTIL, X_SCORE } from '../../../src/schema/identifier';
import * as decayRuleDomain from '../../../src/modules/decayRule/decayRule-domain';
import { type DecayHistory, dayToMs } from '../../../src/modules/decayRule/decayRule-domain';
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';
import { getFakeAuthUser } from '../../utils/domainQueryHelper';
import { INDICATOR_DEFAULT_SCORE } from '../../../src/modules/indicator/indicator-utils';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import { logApp } from '../../../src/config/conf';
import * as indicatorUtils from '../../../src/modules/indicator/indicator-utils';
import * as decayExclusionRuleDomain from '../../../src/modules/decayRule/exclusions/decayExclusionRule-domain';
import type { BasicStoreEntityDecayExclusionRule } from '../../../src/modules/decayRule/exclusions/decayExclusionRule-types';
import { ENTITY_IPV4_ADDR } from '../../../src/schema/stixCyberObservable';

describe('Testing field patch and upsert on indicator for trio {score, valid until, revoked}', () => {
  // Region Mock and Spy setup
  let isDecayEnabledSpy: MockInstance;
  beforeEach(() => {
    isDecayEnabledSpy = vi.spyOn(indicatorUtils, 'isDecayEnabled');
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  // Region cleanup of created data
  const indicatorCreatedIds: string[] = [];
  const createIndicator = async (user: AuthUser, input: IndicatorAddInput): Promise<BasicStoreEntityIndicator> => {
    const indicator = await addIndicator(testContext, user, input);
    indicatorCreatedIds.push(indicator.id);
    return indicator;
  };
  afterAll(async () => {
    const uniqueIds = [...new Set(indicatorCreatedIds)];
    for (let i = 0; i < uniqueIds.length; i += 1) {
      await stixDomainObjectDelete(testContext, ADMIN_USER, uniqueIds[i], ENTITY_TYPE_INDICATOR);
    }
    logApp.info(`${indicatorCreatedIds.length} indicators created and deleted.`);
  });

  // Region date shortcuts
  const todayMorning = new Date();
  todayMorning.setUTCHours(0, 0, 0, 0);
  const inPast90Days = new Date(todayMorning.getTime() - NO_DECAY_DEFAULT_VALID_PERIOD);
  const tomorrow = new Date(todayMorning.getTime() + dayToMs(1));
  const fiveDaysAgo = new Date(todayMorning.getTime() - dayToMs(5));
  const inFiveDays = new Date(todayMorning.getTime() + dayToMs(5));

  const connectorUser = getFakeAuthUser('fakeConnector');
  connectorUser.capabilities = [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }];

  it('decay enabled - valid until and valid from should be in right order', async () => {
    // GIVEN Decay manager is Enabled
    isDecayEnabledSpy.mockResolvedValue(true);

    // AND some indicator
    const indicatorAddInput: IndicatorAddInput = {
      name: 'Indicator domain - with decay - validate valid from and until timeline',
      pattern: '[domain-name:value = \'madgicxads.world\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 87,
    };
    const indicatorWithDecay: BasicStoreEntityIndicator = await createIndicator(ADMIN_USER, indicatorAddInput);
    expect(indicatorWithDecay.decay_history.length).toBe(1);

    // WHEN indicators are updated with wrong dates
    const futureValidFrom = new Date(new Date(indicatorWithDecay.valid_until).getTime() + dayToMs(1));
    const input: EditInput[] = [{ key: VALID_FROM, value: [futureValidFrom.toUTCString()] }];
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay.id, input)).rejects.toThrowError('The valid until date must be greater than the valid from date');

    const pastValidUntil = new Date(new Date(indicatorWithDecay.valid_from).getTime() - dayToMs(1));
    const input2: EditInput[] = [{ key: VALID_UNTIL, value: [pastValidUntil.toUTCString()] }];
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay.id, input2)).rejects.toThrowError('The valid until date must be greater than the valid from date');
  });

  it('decay disabled - valid until and valid from should be in right order', async () => {
    // GIVEN Decay manager is Disabled
    isDecayEnabledSpy.mockResolvedValue(false);

    // AND some indicator
    const indicatorNoDecayInput = {
      name: 'Indicator domain - no decay - validate valid from and until timeline',
      pattern: '[domain-name:value = \'workfront-plus.com\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 85,
      valid_from: inPast90Days,
      valid_until: tomorrow,
    };

    const indicatorWithoutDecay = await createIndicator(ADMIN_USER, indicatorNoDecayInput);
    expect(indicatorWithoutDecay.decay_history).toBeUndefined();

    // WHEN indicators are updated with wrong dates
    const futureValidFrom = new Date(new Date(indicatorWithoutDecay.valid_until).getTime() + dayToMs(1));
    const input: EditInput[] = [{ key: VALID_FROM, value: [futureValidFrom.toUTCString()] }];
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithoutDecay.id, input))
      .rejects.toThrowError('The valid until date must be greater than the valid from date');

    const pastValidUntil = new Date(new Date(indicatorWithoutDecay.valid_from).getTime() - dayToMs(1));
    const input2: EditInput[] = [{ key: VALID_UNTIL, value: [pastValidUntil.toUTCString()] }];
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithoutDecay.id, input2))
      .rejects.toThrowError('The valid until date must be greater than the valid from date');
  });

  it('Creating an indicator with no valid_from should take creation date', async () => {
    isDecayEnabledSpy.mockResolvedValue(true);

    const indicatorInput: IndicatorAddInput = {
      name: 'Indicator domain test - no valid from, but created is present',
      pattern: '[domain-name:value = \'createddate.com\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 83,
      valid_until: tomorrow,
      created: fiveDaysAgo,
    };
    const indicatorWithoutValidFrom = await createIndicator(ADMIN_USER, indicatorInput);
    const indicatorCreated = await findById(testContext, ADMIN_USER, indicatorWithoutValidFrom.id);
    expect(indicatorCreated.valid_from).toBe(fiveDaysAgo.toISOString());
  });

  it('On update, input score should be between 0 and 100', async () => {
    isDecayEnabledSpy.mockResolvedValue(true);
    // GIVEN some indicators
    const indicatorAddInput: IndicatorAddInput = {
      name: 'Indicator domain test - with decay - validate score input',
      pattern: '[domain-name:value = \'pirouette-cacahouette.fr\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 87,
    };
    const indicatorWithDecay = await createIndicator(ADMIN_USER, indicatorAddInput);

    // WHEN indicators are updated with wrong score values
    const inputBelow: EditInput[] = [{ key: X_SCORE, value: [-12] }];
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay.id, inputBelow)).rejects.toThrowError('The score should be an integer between 0 and 100');

    const inputAbove: EditInput[] = [{ key: X_SCORE, value: [305] }];
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay.id, inputAbove)).rejects.toThrowError('The score should be an integer between 0 and 100');
  });

  it('decay enabled - revoke=true compute new score and new valid until', async () => {
    isDecayEnabledSpy.mockResolvedValue(true);
    // GIVEN some indicators
    const indicatorAddInput: IndicatorAddInput = {
      name: 'Indicator domain - decay enabled - revoke=true compute new score and new valid until',
      pattern: '[domain-name:value = \'coucou.fr\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 87,
    };
    const indicatorWithDecay = await createIndicator(ADMIN_USER, indicatorAddInput);
    expect(indicatorWithDecay.revoked).toBeFalsy();

    // --------------------
    // Move revoke from false to true
    // score should be set to the revoke number
    // indicator should have a valid until date in the past
    const inputToRevoke: EditInput[] = [{ key: 'revoked', value: [true] }];
    await indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay.id, inputToRevoke);

    const indicatorUpdatedRevoked = await findById(testContext, ADMIN_USER, indicatorWithDecay.id);
    expect(indicatorUpdatedRevoked.revoked).toBeTruthy();
    expect(indicatorUpdatedRevoked.x_opencti_score).toBe(indicatorWithDecay.decay_applied_rule.decay_revoke_score);
    expect(new Date(indicatorUpdatedRevoked.valid_until).getTime()).toBeLessThan(new Date().getTime());
    const history = indicatorUpdatedRevoked.decay_history;
    history.sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime());
    const lastHistoryEntry = history[0];
    expect(
      lastHistoryEntry?.score,
      'The lifecycle history should have a new entry with the score set to revoke score',
    ).toBe(indicatorWithDecay.decay_applied_rule.decay_revoke_score);
  });

  it('decay enabled - revoke=false compute new score and new valid until', async () => {
    isDecayEnabledSpy.mockResolvedValue(true);

    // GIVEN a revoked indicator
    const indicatorAddInput: IndicatorAddInput = {
      name: 'Indicator domain test with decay - already revoked',
      pattern: '[domain-name:value = \'yeeso.fr\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 95,
    };
    const indicatorWithDecay = await createIndicator(ADMIN_USER, indicatorAddInput);
    const inputToRevoke: EditInput[] = [{ key: 'revoked', value: [true] }];
    await indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay.id, inputToRevoke);
    const indicatorUpdatedRevoked = await findById(testContext, ADMIN_USER, indicatorWithDecay.id);
    expect(indicatorUpdatedRevoked.revoked).toBeTruthy();

    // --------------------
    // WHEN move revoke to false
    // THEN:
    // - score should be back to base score
    // - indicator should have a valid until date in the future
    // - indicator history curve should be updated
    const inputToUnrevoke: EditInput[] = [{ key: 'revoked', value: [false] }];
    await indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay.id, inputToUnrevoke);

    const indicatorUpdatedUnRevoked = await findById(testContext, ADMIN_USER, indicatorWithDecay.id);
    expect(indicatorUpdatedUnRevoked.revoked).toBeFalsy();
    expect(indicatorUpdatedUnRevoked.x_opencti_score).toBeGreaterThan(indicatorWithDecay.decay_applied_rule.decay_revoke_score);
    expect(new Date(indicatorUpdatedUnRevoked.valid_until).getTime()).toBeGreaterThan(new Date().getTime());
    const history = indicatorUpdatedUnRevoked.decay_history;
    history.sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime());
    const lastHistoryEntry = history[0];
    expect(
      lastHistoryEntry.score,
      'The lifecycle history should have a new entry with the score updated',
    ).toBe(indicatorWithDecay.decay_base_score);
  });

  it('no decay - revoke=true compute new score and new valid until', async () => {
    isDecayEnabledSpy.mockResolvedValue(false);

    // GIVEN some indicators
    const indicatorNoDecayInput = {
      name: 'Indicator domain test without decay - revoke=true',
      pattern: '[domain-name:value = \'nodecay.com\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 85,
      valid_from: inPast90Days,
      valid_until: tomorrow,
    };
    const indicatorWithoutDecay = await createIndicator(ADMIN_USER, indicatorNoDecayInput);

    const inputToRevoke: EditInput[] = [{ key: 'revoked', value: [true] }];
    await indicatorEditField(testContext, ADMIN_USER, indicatorWithoutDecay.id, inputToRevoke);

    const indicatorUpdatedRevoked = await findById(testContext, ADMIN_USER, indicatorWithoutDecay.id);
    expect(indicatorUpdatedRevoked.revoked).toBeTruthy();
    expect(indicatorUpdatedRevoked.x_opencti_score).toBe(NO_DECAY_DEFAULT_REVOKED_SCORE);
    expect(new Date(indicatorUpdatedRevoked.valid_until).getTime()).toBeLessThan(new Date().getTime());
  });

  it('should update 2 times with same source and same score be ignored', async () => {
    isDecayEnabledSpy.mockResolvedValue(true);

    // GIVEN an indicator
    const indicatorAddInput: IndicatorAddInput = {
      name: 'Indicator domain test with decay - same source same score',
      pattern: '[domain-name:value = \'twotimes.fr\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 95,
    };
    const indicator = await createIndicator(ADMIN_USER, indicatorAddInput);

    // First update with ADMIN should work fine
    const inputToUpdateScoreUserAdmin: EditInput[] = [{ key: X_SCORE, value: [80] }, { key: 'description', value: ['fieldPatch 1'] }];
    await indicatorEditField(testContext, ADMIN_USER, indicator.id, inputToUpdateScoreUserAdmin);
    const indicatorAfterAdminUpdate80 = await findById(testContext, ADMIN_USER, indicator.id);
    expect(indicatorAfterAdminUpdate80.x_opencti_score).toBe(80);
    expect(indicatorAfterAdminUpdate80.description).toBe('fieldPatch 1');

    // First update with EDITOR should work fine
    const inputToUpdateScoreUserConnector1: EditInput[] = [{ key: X_SCORE, value: [70] }];
    await indicatorEditField(testContext, connectorUser, indicator.id, inputToUpdateScoreUserConnector1);
    const indicatorAfterConnectorUpdate70 = await findById(testContext, ADMIN_USER, indicator.id);
    expect(indicatorAfterConnectorUpdate70.x_opencti_score).toBe(70);

    // Second update with ADMIN , same score should be skipped, but description updated
    const inputToUpdateScoreUserAdmin2: EditInput[] = [{ key: X_SCORE, value: [80] }, { key: 'description', value: ['fieldPatch 2'] }];
    await indicatorEditField(testContext, ADMIN_USER, indicator.id, inputToUpdateScoreUserAdmin2);
    const indicatorAfterAdminUpdate80Again = await findById(testContext, ADMIN_USER, indicator.id);
    expect(indicatorAfterAdminUpdate80Again.x_opencti_score).toBe(70);
    expect(indicatorAfterAdminUpdate80Again.description).toBe('fieldPatch 2');

    // Second update with ADMIN , different score should be taken
    const inputToUpdateScoreUserAdmin3: EditInput[] = [{ key: X_SCORE, value: [75] }];
    await indicatorEditField(testContext, ADMIN_USER, indicator.id, inputToUpdateScoreUserAdmin3);
    const indicatorAfterAdminUpdate75 = await findById(testContext, ADMIN_USER, indicator.id);
    expect(indicatorAfterAdminUpdate75.x_opencti_score).toBe(75);

    // Second update with connector, same score be skipped
    await indicatorEditField(testContext, connectorUser, indicator.id, inputToUpdateScoreUserConnector1);
    const indicatorAfterConnectorUpdate70Again = await findById(testContext, ADMIN_USER, indicator.id);
    expect(indicatorAfterConnectorUpdate70Again.x_opencti_score).toBe(75);

    // Second update with same connector, but different score, should be taken
    const inputToUpdateScoreUserConnector36: EditInput[] = [{ key: X_SCORE, value: [36] }];
    await indicatorEditField(testContext, connectorUser, indicator.id, inputToUpdateScoreUserConnector36);
    const indicatorAfterConnectorUpdate36 = await findById(testContext, ADMIN_USER, indicator.id);
    expect(indicatorAfterConnectorUpdate36.x_opencti_score).toBe(36);
  });

  it('should revoke move to false recompute score on upsert', async () => {
    isDecayEnabledSpy.mockResolvedValue(true);

    // GIVEN an indicator that is created and then revoked.
    const indicatorNoDecayInput = {
      name: 'Indicator domain test without decay',
      pattern: '[domain-name:value = \'createdrevoked.io\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 5,
      valid_from: inPast90Days,
      valid_until: fiveDaysAgo,
      revoked: true,
    };
    const indicatorRevoked = await createIndicator(ADMIN_USER, indicatorNoDecayInput);
    expect(indicatorRevoked.revoked).toBeTruthy();
    expect(indicatorRevoked.x_opencti_score).toBe(5);

    // When the same indicator is created again (upsert) - no score
    const indicatorUpsert = {
      name: 'Indicator domain test without decay',
      pattern: '[domain-name:value = \'createdrevoked.io\']',
      pattern_type: STIX_PATTERN_TYPE,
      valid_from: inPast90Days,
      valid_until: tomorrow,
      revoked: false,
    };
    const indicatorUpsertEntity = await createIndicator(ADMIN_USER, indicatorUpsert);
    expect(indicatorUpsertEntity.revoked).toBeFalsy();
    expect(indicatorUpsertEntity.x_opencti_score).toBe(INDICATOR_DEFAULT_SCORE);
  });

  it('should revoke move to false recompute score on upsert, with score on input', async () => {
    isDecayEnabledSpy.mockResolvedValue(true);

    // GIVEN an indicator that is created and then revoked.
    const indicatorNoDecayInput = {
      name: 'Indicator domain test without decay',
      pattern: '[domain-name:value = \'createdrevoked.io\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 5,
      valid_from: inPast90Days,
      valid_until: fiveDaysAgo,
      revoked: true,
    };
    const indicatorRevoked = await createIndicator(ADMIN_USER, indicatorNoDecayInput);
    expect(indicatorRevoked.revoked).toBeTruthy();
    expect(indicatorRevoked.x_opencti_score).toBe(5);

    // When the same indicator is created again (upsert) - no score
    const indicatorUpsert = {
      name: 'Indicator domain test without decay',
      pattern: '[domain-name:value = \'createdrevoked.io\']',
      pattern_type: STIX_PATTERN_TYPE,
      valid_from: inPast90Days,
      valid_until: tomorrow,
      x_opencti_score: 80,
      revoked: false,
    };
    const indicatorUpsertEntity = await createIndicator(ADMIN_USER, indicatorUpsert);
    expect(indicatorUpsertEntity.revoked).toBeFalsy();
    expect(indicatorUpsertEntity.x_opencti_score).toBe(80);
  });

  it('should preserve IPv4 main observable type when upserting same pattern without explicit main observable type', async () => {
    isDecayEnabledSpy.mockResolvedValue(true);

    const indicatorWithMainObservableType: IndicatorAddInput = {
      name: 'Indicator domain test - preserve IPv4 main observable type on upsert',
      pattern: "[ipv4-addr:value = '8.7.8.9']",
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_main_observable_type: ENTITY_IPV4_ADDR,
    };
    const createdIndicator = await createIndicator(ADMIN_USER, indicatorWithMainObservableType);
    expect((createdIndicator as unknown as { x_opencti_main_observable_type: string }).x_opencti_main_observable_type).toBe(ENTITY_IPV4_ADDR);

    const indicatorWithoutMainObservableType: IndicatorAddInput = {
      name: 'Indicator domain test - preserve IPv4 main observable type on upsert',
      pattern: "[ipv4-addr:value = '8.7.8.9']",
      pattern_type: STIX_PATTERN_TYPE,
    };
    const upsertedIndicator = await createIndicator(ADMIN_USER, indicatorWithoutMainObservableType);
    expect(upsertedIndicator.id).toBe(createdIndicator.id);

    const loadedIndicator = await findById(testContext, ADMIN_USER, createdIndicator.id);
    expect((loadedIndicator as unknown as { x_opencti_main_observable_type: string }).x_opencti_main_observable_type).toBe(ENTITY_IPV4_ADDR);
  });

  it('should upsert 2 times with same source and same score be ignored', async () => {
    isDecayEnabledSpy.mockResolvedValue(true);

    // GIVEN an indicator that is created
    const indicatorInput = {
      name: 'Indicator domain test concurrent upserts',
      pattern: '[domain-name:value = \'jesaisplus.io\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 100,
      valid_from: inPast90Days,
      valid_until: inFiveDays,
    };
    const indicatorCreated = await createIndicator(ADMIN_USER, indicatorInput);
    expect(indicatorCreated.x_opencti_score).toBe(100);

    // Same user decrease score => should be taken
    const indicatorInput2 = {
      name: 'Indicator domain test concurrent upserts',
      pattern: '[domain-name:value = \'jesaisplus.io\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 80,
      valid_from: inPast90Days,
      valid_until: inFiveDays,
    };
    await createIndicator(ADMIN_USER, indicatorInput2);
    const indicatorCreated2 = await findById(testContext, ADMIN_USER, indicatorCreated.id);
    expect(indicatorCreated2.x_opencti_score).toBe(80);

    // When the same indicator is created again (upsert) - with another user => should be taken
    const indicatorUpsert1 = {
      name: 'Indicator domain test concurrent upserts',
      pattern: '[domain-name:value = \'jesaisplus.io\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 75,
      valid_from: inPast90Days,
      valid_until: inFiveDays,
    };
    await createIndicator(connectorUser, indicatorUpsert1);
    const indicatorAfterUpsert1 = await findById(testContext, connectorUser, indicatorCreated.id);
    expect(indicatorAfterUpsert1.x_opencti_score).toBe(75);

    // When the same indicator is created again (upsert) - same user (ADMIN_USER) same score (80) => should be skipped
    const indicatorUpsert2 = {
      name: 'Indicator domain test concurrent upserts',
      pattern: '[domain-name:value = \'jesaisplus.io\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 80,
      valid_from: inPast90Days,
      valid_until: inFiveDays,
    };
    await createIndicator(ADMIN_USER, indicatorUpsert2);
    const indicatorAfterUpsert2 = await findById(testContext, ADMIN_USER, indicatorCreated.id);
    expect(indicatorAfterUpsert2.x_opencti_score).toBe(75); // score update is ignored
  });

  it('should auto-unrevoke indicator when valid_until is updated to a future date', async () => {
    isDecayEnabledSpy.mockResolvedValue(false);

    // GIVEN a revoked indicator without decay
    const indicatorInput = {
      name: 'Indicator domain - auto unrevoke via valid_until',
      pattern: "[domain-name:value = 'autounrevoke.io']",
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 85,
      valid_from: inPast90Days,
      valid_until: fiveDaysAgo,
      revoked: true,
    };
    const indicatorRevoked = await createIndicator(ADMIN_USER, indicatorInput);
    expect(indicatorRevoked.revoked).toBeTruthy();

    // WHEN valid_until is updated to a future date (no explicit revoked field in input)
    const futureDate = new Date(todayMorning.getTime() + dayToMs(30));
    const input: EditInput[] = [{ key: VALID_UNTIL, value: [futureDate.toISOString()] }];
    await indicatorEditField(testContext, ADMIN_USER, indicatorRevoked.id, input);

    // THEN the indicator should be automatically unrevoked (lines 485-487 covered)
    const updatedIndicator = await findById(testContext, ADMIN_USER, indicatorRevoked.id);
    expect(updatedIndicator.revoked).toBeFalsy();
  });

  it('decay enabled - string score equal to base score should not restart decay', async () => {
    isDecayEnabledSpy.mockResolvedValue(true);

    // GIVEN an indicator with decay
    const indicatorAddInput: IndicatorAddInput = {
      name: 'Indicator domain - string score equal to base score',
      pattern: "[domain-name:value = 'stringscore.fr']",
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 87,
    };
    const indicator = await createIndicator(ADMIN_USER, indicatorAddInput);
    const baseScore = indicator.decay_base_score;

    // WHEN score is sent as a string matching the base score (simulating HTML input from frontend)
    // The old code used Array.includes() which would fail on type mismatch string vs number.
    // The new code converts with Number() before comparing, so this should be treated as unchanged.
    const inputWithStringScore: EditInput[] = [{ key: X_SCORE, value: [String(baseScore)] }];
    await indicatorEditField(testContext, ADMIN_USER, indicator.id, inputWithStringScore);

    // THEN decay should NOT be restarted (base_score unchanged = no restart triggered)
    const updatedIndicator = await findById(testContext, ADMIN_USER, indicator.id);
    expect(updatedIndicator.decay_base_score).toBe(baseScore);
  });

  it('no decay - revoke=false should reset score to INDICATOR_DEFAULT_SCORE and set valid dates', async () => {
    isDecayEnabledSpy.mockResolvedValue(false);

    // GIVEN a revoked indicator without decay
    const indicatorNoDecayInput = {
      name: 'Indicator domain - no decay - revoke=false reset',
      pattern: "[domain-name:value = 'nodecayunrevoke.com']",
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 85,
      valid_from: inPast90Days,
      valid_until: tomorrow,
    };
    const indicator = await createIndicator(ADMIN_USER, indicatorNoDecayInput);
    await indicatorEditField(testContext, ADMIN_USER, indicator.id, [{ key: 'revoked', value: [true] }]);
    const revokedIndicator = await findById(testContext, ADMIN_USER, indicator.id);
    expect(revokedIndicator.revoked).toBeTruthy();

    // WHEN revoked is set back to false (no decay path)
    await indicatorEditField(testContext, ADMIN_USER, indicator.id, [{ key: 'revoked', value: [false] }]);

    // THEN score should be INDICATOR_DEFAULT_SCORE, valid_until in future, valid_from updated (lines 538-542)
    const unrevokedIndicator = await findById(testContext, ADMIN_USER, indicator.id);
    expect(unrevokedIndicator.revoked).toBeFalsy();
    expect(unrevokedIndicator.x_opencti_score).toBe(INDICATOR_DEFAULT_SCORE);
    expect(new Date(unrevokedIndicator.valid_until).getTime()).toBeGreaterThan(new Date().getTime());
    expect(new Date(unrevokedIndicator.valid_from).getTime()).toBeLessThanOrEqual(new Date().getTime() + 1000);
  });

  it('decay enabled - updating only valid_until should be kept as-is (safeguard line 547)', async () => {
    isDecayEnabledSpy.mockResolvedValue(true);

    // GIVEN an indicator with decay, not revoked, no score change
    const indicatorAddInput: IndicatorAddInput = {
      name: 'Indicator domain - safeguard valid_until passthrough',
      pattern: "[domain-name:value = 'validuntilpassthrough.fr']",
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 87,
    };
    const indicator = await createIndicator(ADMIN_USER, indicatorAddInput);

    // WHEN only valid_until is updated to a future date (no score, not revoked → safeguard line 547 applies)
    const targetDate = new Date(todayMorning.getTime() + dayToMs(60));
    await indicatorEditField(testContext, ADMIN_USER, indicator.id, [
      { key: VALID_UNTIL, value: [targetDate.toISOString()] },
    ]);

    // THEN valid_until should match the exact value we passed (safeguard pushed validUntilEditInput)
    const updatedIndicator = await findById(testContext, ADMIN_USER, indicator.id);
    expect(new Date(updatedIndicator.valid_until).toISOString()).toBe(targetDate.toISOString());
  });

  it('no decay - revoked and score sent together: revoked should still be persisted', async () => {
    isDecayEnabledSpy.mockResolvedValue(false);

    // GIVEN an indicator without decay
    const indicatorInput = {
      name: 'Indicator domain - revoked + score simultaneously',
      pattern: "[domain-name:value = 'revokedwithscore.io']",
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 70,
      valid_from: inPast90Days,
      valid_until: tomorrow,
    };
    const indicator = await createIndicator(ADMIN_USER, indicatorInput);
    expect(indicator.revoked).toBeFalsy();

    // WHEN revoked and score are sent together
    // The guard `if (revokedEditInput && !validUntilEditInput && !scoreEditInput)` is skipped,
    // so revokedEditInput is NOT pushed in the first block.
    // The safeguard at line 550-552 must push it.
    const input: EditInput[] = [
      { key: 'revoked', value: [true] },
      { key: X_SCORE, value: [50] },
    ];
    await indicatorEditField(testContext, ADMIN_USER, indicator.id, input);

    // THEN revoked must still be persisted (safeguard line 551 covered)
    const updatedIndicator = await findById(testContext, ADMIN_USER, indicator.id);
    expect(updatedIndicator.revoked).toBeTruthy();
  });

  it('should upsert 2 times with same source and same score be taken - without decay', async () => {
    isDecayEnabledSpy.mockResolvedValue(false);

    // GIVEN an indicator that is created
    const indicatorInput = {
      name: 'Indicator domain test concurrent upserts',
      pattern: '[domain-name:value = \'jesaisplus2.io\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 100,
      valid_from: inPast90Days,
      valid_until: inFiveDays,
    };
    const indicatorCreated = await createIndicator(ADMIN_USER, indicatorInput);
    expect(indicatorCreated.x_opencti_score).toBe(100);

    // Same user decrease score => should be taken
    const indicatorInput2 = {
      name: 'Indicator domain test concurrent upserts',
      pattern: '[domain-name:value = \'jesaisplus2.io\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 81,
      valid_from: inPast90Days,
      valid_until: inFiveDays,
    };
    await createIndicator(ADMIN_USER, indicatorInput2);
    const indicatorCreated2 = await findById(testContext, ADMIN_USER, indicatorCreated.id);
    expect(indicatorCreated2.x_opencti_score).toBe(81);

    // When the same indicator is created again (upsert) - with another user => should be taken
    const indicatorUpsert1 = {
      name: 'Indicator domain test concurrent upserts',
      pattern: '[domain-name:value = \'jesaisplus2.io\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 75,
      valid_from: inPast90Days,
      valid_until: inFiveDays,
    };
    await createIndicator(connectorUser, indicatorUpsert1);
    const indicatorAfterUpsert1 = await findById(testContext, connectorUser, indicatorCreated.id);
    expect(indicatorAfterUpsert1.x_opencti_score).toBe(75);

    // When the same indicator is created again (upsert) - same user (ADMIN_USER) same score (80) => should be skipped
    const indicatorUpsert2 = {
      name: 'Indicator domain test concurrent upserts',
      pattern: '[domain-name:value = \'jesaisplus2.io\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 80,
      valid_from: inPast90Days,
      valid_until: inFiveDays,
    };
    await createIndicator(ADMIN_USER, indicatorUpsert2);
    const indicatorAfterUpsert2 = await findById(testContext, ADMIN_USER, indicatorCreated.id);
    expect(indicatorAfterUpsert2.x_opencti_score).toBe(80); // score update is ignored
  });

  // Region Decay exclusion rule tests (issue #16365)
  // A fake exclusion rule to be returned by the mocked checkDecayExclusionRules
  const fakeExclusionRule = {
    id: 'fake-decay-exclusion-rule-id',
    internal_id: 'fake-decay-exclusion-rule-id',
    name: 'Test exclusion rule',
    description: '',
    active: true,
    decay_exclusion_filters: '{}',
    created_at: new Date().toISOString(),
  } as unknown as BasicStoreEntityDecayExclusionRule;

  it('decay excluded indicator - upsert with unchanged score should NOT overwrite valid_until, revoked', async () => {
    // GIVEN decay is enabled and an exclusion rule matches this indicator
    isDecayEnabledSpy.mockResolvedValue(true);
    vi.spyOn(decayExclusionRuleDomain, 'getActiveDecayExclusionRules').mockResolvedValue([fakeExclusionRule]);
    vi.spyOn(decayExclusionRuleDomain, 'checkDecayExclusionRules').mockResolvedValue(fakeExclusionRule);

    const indicatorInput: IndicatorAddInput = {
      name: 'Indicator domain - exclusion rule - upsert score unchanged',
      pattern: "[domain-name:value = 'excluded-upsert-unchanged.test']",
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 80,
      valid_from: todayMorning.toISOString(),
      valid_until: inFiveDays.toISOString(),
    };
    const indicatorCreated = await createIndicator(ADMIN_USER, indicatorInput);

    // Check the exclusion rule was applied at creation
    expect(indicatorCreated.decay_exclusion_applied_rule).toBeDefined();
    expect(indicatorCreated.x_opencti_score).toBe(80);
    const originalValidUntil = indicatorCreated.valid_until;

    // WHEN the same indicator is re-ingested with the same score but a different valid_until (simulating a connector cycle)
    const indicatorUpsertInput: IndicatorAddInput = {
      name: 'Indicator domain - exclusion rule - upsert score unchanged',
      pattern: "[domain-name:value = 'excluded-upsert-unchanged.test']",
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 80, // unchanged score
      valid_from: todayMorning.toISOString(),
      valid_until: tomorrow.toISOString(), // different valid_until — should NOT be applied
    };
    await createIndicator(connectorUser, indicatorUpsertInput);
    const indicatorAfterUpsert = await findById(testContext, ADMIN_USER, indicatorCreated.id);

    // THEN valid_until, revoked and score are preserved (guard from issue #16365 fix)
    expect(indicatorAfterUpsert.x_opencti_score).toBe(80);
    expect(indicatorAfterUpsert.valid_until).toBe(originalValidUntil);
    expect(indicatorAfterUpsert.revoked).toBeFalsy();
  });

  it('decay excluded indicator - upsert with changed score SHOULD update valid_until', async () => {
    // GIVEN decay is enabled and an exclusion rule matches this indicator
    isDecayEnabledSpy.mockResolvedValue(true);
    vi.spyOn(decayExclusionRuleDomain, 'getActiveDecayExclusionRules').mockResolvedValue([fakeExclusionRule]);
    vi.spyOn(decayExclusionRuleDomain, 'checkDecayExclusionRules').mockResolvedValue(fakeExclusionRule);

    const indicatorInput: IndicatorAddInput = {
      name: 'Indicator domain - exclusion rule - upsert score changed',
      pattern: "[domain-name:value = 'excluded-upsert-changed.test']",
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 80,
      valid_from: todayMorning.toISOString(),
      valid_until: inFiveDays.toISOString(),
    };
    const indicatorCreated = await createIndicator(ADMIN_USER, indicatorInput);
    expect(indicatorCreated.decay_exclusion_applied_rule).toBeDefined();
    expect(indicatorCreated.x_opencti_score).toBe(80);

    // WHEN the same indicator is re-ingested with a different score and a different valid_until
    const indicatorUpsertInput: IndicatorAddInput = {
      name: 'Indicator domain - exclusion rule - upsert score changed',
      pattern: "[domain-name:value = 'excluded-upsert-changed.test']",
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 60, // score changed — guard should NOT block the update
      valid_from: todayMorning.toISOString(),
      valid_until: tomorrow.toISOString(),
    };
    await createIndicator(connectorUser, indicatorUpsertInput);
    const indicatorAfterUpsert = await findById(testContext, ADMIN_USER, indicatorCreated.id);

    // THEN the new score is accepted
    expect(indicatorAfterUpsert.x_opencti_score).toBe(60);
  });
});

// ─── Unit helpers (no DB required) ──────────────────────────────────────────

const mockContext = {} as unknown as AuthContext;
const mockUser = { id: 'user-test' } as unknown as AuthUser;

const makeDecayRule = (overrides: Partial<IndicatorDecayRule> = {}): IndicatorDecayRule => ({
  decay_rule_id: 'rule-1',
  decay_lifetime: 365,
  decay_pound: 3,
  decay_points: [80, 60, 40, 20],
  decay_revoke_score: 10,
  ...overrides,
});

const makeHistoryPoint = (score: number, updated_by = 'user-1'): DecayHistory => ({
  updated_at: new Date('2024-01-01T00:00:00Z'),
  score,
  updated_by,
});

const makeIndicator = (overrides: Partial<BasicStoreEntityIndicator> = {}): BasicStoreEntityIndicator => ({
  id: 'indicator-1',
  x_opencti_score: 75,
  decay_base_score: 90,
  decay_base_score_date: new Date('2024-01-01T00:00:00Z'),
  decay_applied_rule: makeDecayRule(),
  decay_history: [makeHistoryPoint(90)],
  valid_from: new Date('2024-01-01T00:00:00Z'),
  ...overrides,
} as unknown as BasicStoreEntityIndicator);

// ─── computeIndicatorDecayHistory ───────────────────────────────────────────

describe('computeIndicatorDecayHistory', () => {
  it('should append the new point to the history when under the limit', () => {
    const history: DecayHistory[] = [makeHistoryPoint(90), makeHistoryPoint(80)];
    const newPoint = makeHistoryPoint(70);
    const result = computeIndicatorDecayHistory(history, newPoint);
    expect(result).toHaveLength(3);
    expect(result[2].score).toBe(70);
  });

  it('should keep exactly MAX_DECAY_HISTORY_POINTS entries when limit is reached', () => {
    const history: DecayHistory[] = Array.from({ length: MAX_DECAY_HISTORY_POINTS - 1 }, (_, i) =>
      makeHistoryPoint(100 - i));
    const result = computeIndicatorDecayHistory(history, makeHistoryPoint(1));
    expect(result).toHaveLength(MAX_DECAY_HISTORY_POINTS);
  });

  it('should trim history to MAX_DECAY_HISTORY_POINTS when limit is exceeded', () => {
    const history: DecayHistory[] = Array.from({ length: MAX_DECAY_HISTORY_POINTS }, (_, i) =>
      makeHistoryPoint(100 - i));
    const result = computeIndicatorDecayHistory(history, makeHistoryPoint(0, 'user-new'));
    expect(result).toHaveLength(MAX_DECAY_HISTORY_POINTS);
  });

  it('should preserve the first 25 entries and the last 25 entries after trimming', () => {
    const history: DecayHistory[] = Array.from({ length: MAX_DECAY_HISTORY_POINTS }, (_, i) =>
      ({ updated_at: new Date(), score: 100 - i, updated_by: `user-${i}` }));
    const newPoint: DecayHistory = { updated_at: new Date(), score: 0, updated_by: 'user-last' };
    const result = computeIndicatorDecayHistory(history, newPoint);
    const half = MAX_DECAY_HISTORY_POINTS / 2;
    expect(result[0].score).toBe(100);
    expect(result[half - 1].score).toBe(100 - (half - 1));
    expect(result[result.length - 1].updated_by).toBe('user-last');
  });

  it('should work correctly with an empty history', () => {
    const result = computeIndicatorDecayHistory([], makeHistoryPoint(90));
    expect(result).toHaveLength(1);
    expect(result[0].score).toBe(90);
  });
});

// ─── computeLiveScore ────────────────────────────────────────────────────────

describe('computeLiveScore', () => {
  beforeEach(() => {
    vi.spyOn(decayRuleDomain, 'computeScoreFromExpectedTime').mockReturnValue(72.7);
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should compute a live score based on decay rule when all fields are present', () => {
    const indicator = makeIndicator({
      decay_base_score_date: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
    });
    const result = computeLiveScore(indicator);
    expect(decayRuleDomain.computeScoreFromExpectedTime).toHaveBeenCalled();
    expect(result).toBe(Math.round(72.7));
  });

  it('should return x_opencti_score when decay_base_score_date is missing', () => {
    const indicator = makeIndicator({ decay_base_score_date: undefined as any });
    const result = computeLiveScore(indicator);
    expect(result).toBe(indicator.x_opencti_score);
    expect(decayRuleDomain.computeScoreFromExpectedTime).not.toHaveBeenCalled();
  });

  it('should return x_opencti_score when decay_applied_rule is missing', () => {
    const indicator = makeIndicator({ decay_applied_rule: undefined as any });
    expect(computeLiveScore(indicator)).toBe(indicator.x_opencti_score);
  });

  it('should return x_opencti_score when decay_base_score is 0 (falsy)', () => {
    const indicator = makeIndicator({ decay_base_score: 0 });
    expect(computeLiveScore(indicator)).toBe(indicator.x_opencti_score);
  });
});

// ─── computeLivePoints ───────────────────────────────────────────────────────

describe('computeLivePoints', () => {
  beforeEach(() => {
    vi.spyOn(decayRuleDomain, 'computeTimeFromExpectedScore').mockReturnValue(90);
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return an empty array when decay_applied_rule is missing', () => {
    expect(computeLivePoints(makeIndicator({ decay_applied_rule: undefined as any }))).toEqual([]);
  });

  it('should return an empty array when decay_points is missing', () => {
    expect(computeLivePoints(makeIndicator({ decay_applied_rule: makeDecayRule({ decay_points: undefined as any }) }))).toEqual([]);
  });

  it('should return an empty array when decay_base_score_date is missing', () => {
    expect(computeLivePoints(makeIndicator({ decay_base_score_date: undefined as any }))).toEqual([]);
  });

  it('should only include decay points strictly lower than current x_opencti_score', () => {
    // x_opencti_score = 75, decay_points = [80, 60, 40, 20], decay_revoke_score = 10 → 4 points < 75
    const result = computeLivePoints(makeIndicator({ x_opencti_score: 75 }));
    expect(decayRuleDomain.computeTimeFromExpectedScore).toHaveBeenCalledTimes(4);
    result.forEach((p) => expect(p.score).toBeLessThan(75));
  });

  it('should return no points when x_opencti_score is already at the revoke threshold', () => {
    const indicator = makeIndicator({
      x_opencti_score: 10,
      decay_applied_rule: makeDecayRule({ decay_points: [80, 60, 40, 20], decay_revoke_score: 10 }),
    });
    expect(computeLivePoints(indicator)).toHaveLength(0);
  });

  it('should include a point for the revoke score', () => {
    const scores = computeLivePoints(makeIndicator({ x_opencti_score: 100 })).map((p) => p.score);
    expect(scores).toContain(10);
  });

  it('should return Date objects in the updated_at field of each point', () => {
    computeLivePoints(makeIndicator({ x_opencti_score: 100 }))
      .forEach((p) => expect(p.updated_at).toBeInstanceOf(Date));
  });
});

// ─── computeIndicatorDecayPatch ──────────────────────────────────────────────

describe('computeIndicatorDecayPatch', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return null when decay_applied_rule is missing', () => {
    expect(computeIndicatorDecayPatch(mockContext, mockUser, makeIndicator({ decay_applied_rule: undefined as any }))).toBeNull();
  });

  it('should return null when decay_points is missing', () => {
    expect(computeIndicatorDecayPatch(mockContext, mockUser, makeIndicator({
      decay_applied_rule: makeDecayRule({ decay_points: undefined as any }),
    }))).toBeNull();
  });

  it('should set revoked=true and x_opencti_detection=false when new score reaches revoke threshold', () => {
    const indicator = makeIndicator({
      x_opencti_score: 15,
      decay_applied_rule: makeDecayRule({ decay_points: [80, 60, 40, 20], decay_revoke_score: 10 }),
    });
    const patch = computeIndicatorDecayPatch(mockContext, mockUser, indicator);
    expect(patch?.revoked).toBe(true);
    expect(patch?.x_opencti_detection).toBe(false);
    expect(patch?.x_opencti_score).toBe(10);
  });

  it('should set decay_next_reaction_date when next score is above revoke threshold', () => {
    vi.spyOn(decayRuleDomain, 'computeNextScoreReactionDate').mockReturnValue(
      moment().add(30, 'days').toDate() as any,
    );
    const indicator = makeIndicator({
      x_opencti_score: 90,
      decay_applied_rule: makeDecayRule({ decay_points: [80, 60, 40, 20], decay_revoke_score: 10 }),
    });
    const patch = computeIndicatorDecayPatch(mockContext, mockUser, indicator);
    expect(patch?.x_opencti_score).toBe(80);
    expect(patch?.revoked).toBeUndefined();
    expect(patch?.decay_next_reaction_date).toBeDefined();
  });

  it('should append a new entry to decay_history in the patch', () => {
    vi.spyOn(decayRuleDomain, 'computeNextScoreReactionDate').mockReturnValue(
      moment().add(30, 'days').toDate() as any,
    );
    const patch = computeIndicatorDecayPatch(mockContext, mockUser, makeIndicator({ x_opencti_score: 90 }));
    const lastEntry = patch!.decay_history![patch!.decay_history!.length - 1];
    expect(lastEntry.updated_by).toBe(mockUser.id);
    expect(lastEntry.score).toBe(80);
  });

  it('should use decay_revoke_score as fallback when no decay_point is below current score', () => {
    const indicator = makeIndicator({
      x_opencti_score: 5,
      decay_applied_rule: makeDecayRule({ decay_points: [80, 60, 40, 20], decay_revoke_score: 10 }),
    });
    const patch = computeIndicatorDecayPatch(mockContext, mockUser, indicator);
    expect(patch?.x_opencti_score).toBe(10);
    expect(patch?.revoked).toBe(true);
  });
});
