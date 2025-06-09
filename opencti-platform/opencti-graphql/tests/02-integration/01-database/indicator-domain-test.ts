import { afterAll, describe, it, expect } from 'vitest';
import {
  addIndicator,
  findById,
  INDICATOR_DEFAULT_SCORE,
  indicatorEditField,
  NO_DECAY_DEFAULT_REVOKED_SCORE,
  NO_DECAY_DEFAULT_VALID_PERIOD
} from '../../../src/modules/indicator/indicator-domain';
import type { EditInput, IndicatorAddInput } from '../../../src/generated/graphql';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { type BasicStoreEntityIndicator, ENTITY_TYPE_INDICATOR } from '../../../src/modules/indicator/indicator-types';
import { STIX_PATTERN_TYPE } from '../../../src/utils/syntax';
import { VALID_FROM, VALID_UNTIL, X_SCORE } from '../../../src/schema/identifier';
import { createEntity } from '../../../src/database/middleware';
import { dayToMs } from '../../../src/modules/decayRule/decayRule-domain';
import { logApp } from '../../../src/config/conf';
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';

describe('Testing field patch on indicator for trio {score, valid until, revoked}', () => {
  const indicatorCreatedIds : string[] = [];
  const todayMorning = new Date();
  todayMorning.setUTCHours(0, 0, 0, 0);
  const inPast90Days = new Date(todayMorning.getTime() - NO_DECAY_DEFAULT_VALID_PERIOD);
  const tomorrow = new Date(todayMorning.getTime() + dayToMs(1));

  const createIndicator = async (input: IndicatorAddInput, withDecay: boolean): Promise<BasicStoreEntityIndicator> => {
    if (withDecay) {
      const indicatorWithDecay = await addIndicator(testContext, ADMIN_USER, input);
      indicatorCreatedIds.push(indicatorWithDecay.id);
      if (!indicatorWithDecay.revoked) {
        expect(indicatorWithDecay.decay_applied_rule).toBeDefined();
        expect(indicatorWithDecay.decay_applied_rule.decay_revoke_score).toBeDefined();
      }
      return indicatorWithDecay;
    }

    // bypass addIndicator to have indicator without decay rules
    const indicatorWithoutDecay = await createEntity(testContext, ADMIN_USER, input, ENTITY_TYPE_INDICATOR) as BasicStoreEntityIndicator;
    indicatorCreatedIds.push(indicatorWithoutDecay.id);
    expect(indicatorWithoutDecay.decay_applied_rule).toBeUndefined();
    return indicatorWithoutDecay;
  };

  afterAll(async () => {
    for (let i = 0; i < indicatorCreatedIds.length; i += 1) {
      await stixDomainObjectDelete(testContext, ADMIN_USER, indicatorCreatedIds[i]);
    }
    logApp.info(`${indicatorCreatedIds.length} indicators created and deleted.`);
  });

  it('valid until and valid from should be in right order', async () => {
    // GIVEN some indicators
    const indicatorAddInput: IndicatorAddInput = {
      name: 'Indicator domain - with decay - validate valid from and until timeline',
      pattern: '[domain-name:value = \'madgicxads.world\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 87,
    };
    const indicatorWithDecay = await createIndicator(indicatorAddInput, true);

    const indicatorNoDecayInput = {
      name: 'Indicator domain - no decay - validate valid from and until timeline',
      pattern: '[domain-name:value = \'workfront-plus.com\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 85,
      valid_from: inPast90Days,
      valid_until: tomorrow
    };

    const indicatorWithoutDecay = await createIndicator(indicatorNoDecayInput, false);

    // WHEN indicators are updated with wrong dates
    const futureValidFrom = new Date(new Date(indicatorWithDecay.valid_until).getTime() + dayToMs(1));
    const input: EditInput[] = [{ key: VALID_FROM, value: [futureValidFrom.toUTCString()] }];
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay.id, input)).rejects.toThrowError('The valid until date must be greater than the valid from date');
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithoutDecay.id, input))
      .rejects.toThrowError('The valid until date must be greater than the valid from date');

    const pastValidUntil = new Date(new Date(indicatorWithDecay.valid_from).getTime() - dayToMs(1));
    const input2: EditInput[] = [{ key: VALID_UNTIL, value: [pastValidUntil.toUTCString()] }];
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay.id, input2)).rejects.toThrowError('The valid until date must be greater than the valid from date');
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithoutDecay.id, input))
      .rejects.toThrowError('The valid until date must be greater than the valid from date');
  });

  it('On update, input score should be between 0 and 100', async () => {
    // GIVEN some indicators
    const indicatorAddInput: IndicatorAddInput = {
      name: 'Indicator domain test - with decay - validate score input',
      pattern: '[domain-name:value = \'pirouette-cacahouette.fr\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 87,
    };
    const indicatorWithDecay = await createIndicator(indicatorAddInput, true);

    const indicatorNoDecayInput = {
      name: 'Indicator domain test - no decay - validate score input',
      pattern: '[domain-name:value = \'peekaboo.com\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 85,
      valid_from: inPast90Days,
      valid_until: tomorrow
    };
    const indicatorWithoutDecay = await createIndicator(indicatorNoDecayInput, false);

    // WHEN indicators are updated with wrong score values
    const inputBelow: EditInput[] = [{ key: X_SCORE, value: [-12] }];
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay.id, inputBelow)).rejects.toThrowError('The score should be an integer between 0 and 100');
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithoutDecay.id, inputBelow)).rejects.toThrowError('The score should be an integer between 0 and 100');

    const inputAbove: EditInput[] = [{ key: X_SCORE, value: [305] }];
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay.id, inputAbove)).rejects.toThrowError('The score should be an integer between 0 and 100');
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithoutDecay.id, inputAbove)).rejects.toThrowError('The score should be an integer between 0 and 100');
  });

  it('decay enabled - revoke=true compute new score and new valid until', async () => { // todo
    // GIVEN some indicators
    const indicatorAddInput: IndicatorAddInput = {
      name: 'Indicator domain - decay enabled - revoke=true compute new score and new valid until',
      pattern: '[domain-name:value = \'coucou.fr\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 87,
    };
    const indicatorWithDecay = await createIndicator(indicatorAddInput, true);
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
    logApp.info('Indicator lastHistoryEntry', lastHistoryEntry);
    expect(
      lastHistoryEntry?.score,
      'The lifecycle history should have a new entry with the score set to revoke score'
    ).toBe(indicatorWithDecay.decay_applied_rule.decay_revoke_score);
  });

  it('decay enabled - revoke=false compute new score and new valid until', async () => {
    // GIVEN a revoked indicator
    const indicatorAddInput: IndicatorAddInput = {
      name: 'Indicator domain test with decay - already revoked',
      pattern: '[domain-name:value = \'yeeso.fr\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 95,
    };
    const indicatorWithDecay = await createIndicator(indicatorAddInput, true);
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
    logApp.info('Indicator after revoke true then false ICI', indicatorUpdatedUnRevoked);
    expect(indicatorUpdatedUnRevoked.revoked).toBeFalsy();
    expect(indicatorUpdatedUnRevoked.x_opencti_score).toBeGreaterThan(indicatorWithDecay.decay_applied_rule.decay_revoke_score);
    expect(new Date(indicatorUpdatedUnRevoked.valid_until).getTime()).toBeGreaterThan(new Date().getTime());
    const history = indicatorUpdatedUnRevoked.decay_history;
    history.sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime());
    const lastHistoryEntry = history[0];
    logApp.info('Indicator lastHistoryEntry ICI', lastHistoryEntry);
    expect(
      lastHistoryEntry.score,
      'The lifecycle history should have a new entry with the score updated'
    ).toBe(indicatorWithDecay.decay_base_score);
  });

  it('no decay - revoke=true compute new score and new valid until', async () => {
    // GIVEN some indicators
    const indicatorNoDecayInput = {
      name: 'Indicator domain test without decay - revoke=true',
      pattern: '[domain-name:value = \'nodecay.com\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 85,
      valid_from: inPast90Days,
      valid_until: tomorrow
    };
    const indicatorWithoutDecay = await createIndicator(indicatorNoDecayInput, false);

    const inputToRevoke: EditInput[] = [{ key: 'revoked', value: [true] }];
    await indicatorEditField(testContext, ADMIN_USER, indicatorWithoutDecay.id, inputToRevoke);

    const indicatorUpdatedRevoked = await findById(testContext, ADMIN_USER, indicatorWithoutDecay.id);
    expect(indicatorUpdatedRevoked.revoked).toBeTruthy();
    expect(indicatorUpdatedRevoked.x_opencti_score).toBe(NO_DECAY_DEFAULT_REVOKED_SCORE);
    expect(new Date(indicatorUpdatedRevoked.valid_until).getTime()).toBeLessThan(new Date().getTime());
  });

  it('no decay - revoke=false compute new score and new valid until', async () => {
    // GIVEN an indicator that is created and then revoked.
    const indicatorNoDecayInput = {
      name: 'Indicator domain test without decay',
      pattern: '[domain-name:value = \'plouf.io\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 85,
      valid_from: inPast90Days,
      valid_until: tomorrow
    };
    const indicatorWithoutDecay = await createIndicator(indicatorNoDecayInput, false);
    const inputToRevoke: EditInput[] = [{ key: 'revoked', value: [true] }];
    await indicatorEditField(testContext, ADMIN_USER, indicatorWithoutDecay.id, inputToRevoke);
    const indicatorUpdatedRevoked = await findById(testContext, ADMIN_USER, indicatorWithoutDecay.id);
    expect(indicatorUpdatedRevoked.revoked).toBeTruthy();

    // --------------------
    // WHEN move revoke to false
    // THEN:
    // - score should be back to default score
    // - indicator should have a valid until date in the future
    const inputToUnrevoke: EditInput[] = [{ key: 'revoked', value: [false] }];
    await indicatorEditField(testContext, ADMIN_USER, indicatorWithoutDecay.id, inputToUnrevoke);

    const indicatorUpdatedUnRevoked = await findById(testContext, ADMIN_USER, indicatorWithoutDecay.id);
    expect(indicatorUpdatedUnRevoked.revoked).toBeFalsy();
    expect(indicatorUpdatedUnRevoked.x_opencti_score).toBe(INDICATOR_DEFAULT_SCORE);
    expect(new Date(indicatorUpdatedUnRevoked.valid_until).getTime()).toBeGreaterThan(new Date().getTime());
  });
});
