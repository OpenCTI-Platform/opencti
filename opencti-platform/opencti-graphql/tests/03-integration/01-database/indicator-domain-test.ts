import { afterAll, describe, it, expect, vi, type MockInstance, beforeEach, afterEach } from 'vitest';
import { addIndicator, findById, indicatorEditField, NO_DECAY_DEFAULT_REVOKED_SCORE, NO_DECAY_DEFAULT_VALID_PERIOD } from '../../../src/modules/indicator/indicator-domain';
import type { EditInput, IndicatorAddInput } from '../../../src/generated/graphql';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { type BasicStoreEntityIndicator } from '../../../src/modules/indicator/indicator-types';
import { STIX_PATTERN_TYPE } from '../../../src/utils/syntax';
import { VALID_FROM, VALID_UNTIL, X_SCORE } from '../../../src/schema/identifier';
import { dayToMs } from '../../../src/modules/decayRule/decayRule-domain';
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';
import { getFakeAuthUser } from '../../utils/domainQueryHelper';
import { INDICATOR_DEFAULT_SCORE } from '../../../src/modules/indicator/indicator-utils';
import type { AuthUser } from '../../../src/types/user';
import { logApp } from '../../../src/config/conf';
import * as indicatorUtils from '../../../src/modules/indicator/indicator-utils';

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
  const indicatorCreatedIds : string[] = [];
  const createIndicator = async (user:AuthUser, input: IndicatorAddInput): Promise<BasicStoreEntityIndicator> => {
    const indicator = await addIndicator(testContext, user, input);
    indicatorCreatedIds.push(indicator.id);
    return indicator;
  };
  afterAll(async () => {
    const uniqueIds = [...new Set(indicatorCreatedIds)];
    for (let i = 0; i < uniqueIds.length; i += 1) {
      await stixDomainObjectDelete(testContext, ADMIN_USER, uniqueIds[i]);
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
      valid_until: tomorrow
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
      created: fiveDaysAgo
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
      'The lifecycle history should have a new entry with the score set to revoke score'
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
      'The lifecycle history should have a new entry with the score updated'
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
      valid_until: tomorrow
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
      revoked: true
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
      revoked: false
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
      revoked: true
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
      revoked: false
    };
    const indicatorUpsertEntity = await createIndicator(ADMIN_USER, indicatorUpsert);
    expect(indicatorUpsertEntity.revoked).toBeFalsy();
    expect(indicatorUpsertEntity.x_opencti_score).toBe(80);
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
});
