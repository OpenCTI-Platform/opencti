import { afterAll, beforeAll, describe, it, expect } from 'vitest';
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
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';
import { type BasicStoreEntityIndicator, ENTITY_TYPE_INDICATOR } from '../../../src/modules/indicator/indicator-types';
import { STIX_PATTERN_TYPE } from '../../../src/utils/syntax';
import { VALID_FROM, VALID_UNTIL, X_SCORE } from '../../../src/schema/identifier';
import { utcDate } from '../../../src/utils/format';
import { createEntity } from '../../../src/database/middleware';
import { dayToMs } from '../../../src/modules/decayRule/decayRule-domain';
import { logApp } from '../../../src/config/conf';

describe('Testing field patch on indicator for trio {score, valid until, revoked}', () => {
  let indicatorWithDecay: BasicStoreEntityIndicator;
  let indicatorWithDecay2: BasicStoreEntityIndicator;
  let indicatorWithDecay3: BasicStoreEntityIndicator;
  let indicatorWithoutDecay: BasicStoreEntityIndicator;
  let indicatorWithoutDecay2: BasicStoreEntityIndicator;

  beforeAll(async () => {
    const indicatorAddInput: IndicatorAddInput = {
      name: 'Indicator domain test with decay',
      pattern: '[file:hashes.\'SHA-256\' = \'4bac27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f877\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 87,
    };
    indicatorWithDecay = await addIndicator(testContext, ADMIN_USER, indicatorAddInput);
    expect(indicatorWithDecay.revoked).toBeFalsy();
    expect(indicatorWithDecay.decay_applied_rule).toBeDefined();
    expect(indicatorWithDecay.decay_applied_rule.decay_revoke_score).toBeDefined();
    expect(indicatorWithDecay.x_opencti_score).toBeGreaterThan(indicatorWithDecay.decay_applied_rule.decay_revoke_score);
    expect(new Date(indicatorWithDecay.valid_until).getTime()).toBeGreaterThan(new Date().getTime());

    const indicatorAddInput2: IndicatorAddInput = {
      name: 'Indicator domain test with decay 2',
      pattern: '[file:hashes.\'SHA-256\' = \'4bac27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f666\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 91,
    };
    indicatorWithDecay2 = await addIndicator(testContext, ADMIN_USER, indicatorAddInput2);
    expect(indicatorWithDecay2.revoked).toBeFalsy();
    expect(indicatorWithDecay2.decay_applied_rule).toBeDefined();
    expect(indicatorWithDecay2.decay_applied_rule.decay_revoke_score).toBeDefined();
    expect(indicatorWithDecay2.x_opencti_score).toBeGreaterThan(indicatorWithDecay2.decay_applied_rule.decay_revoke_score);
    expect(new Date(indicatorWithDecay2.valid_until).getTime()).toBeGreaterThan(new Date().getTime());

    const indicatorAddInput3: IndicatorAddInput = {
      name: 'Indicator domain test with decay 3',
      pattern: '[domain-name:value = \'montest.fr\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 99,
    };
    indicatorWithDecay3 = await addIndicator(testContext, ADMIN_USER, indicatorAddInput3);
    expect(indicatorWithDecay3.revoked).toBeFalsy();
    expect(indicatorWithDecay3.decay_applied_rule).toBeDefined();
    expect(indicatorWithDecay3.decay_applied_rule.decay_revoke_score).toBeDefined();
    expect(indicatorWithDecay3.x_opencti_score).toBeGreaterThan(indicatorWithDecay3.decay_applied_rule.decay_revoke_score);
    expect(new Date(indicatorWithDecay3.valid_until).getTime()).toBeGreaterThan(new Date().getTime());

    const inPast90Days = new Date(new Date().getTime() - NO_DECAY_DEFAULT_VALID_PERIOD);
    const tomorow = new Date(new Date().getTime() + dayToMs(1));
    const indicatorNoDecayInput = {
      name: 'Indicator domain test without decay',
      pattern: '[file:hashes.\'SHA-256\' = \'aaa27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f666\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 85,
      valid_from: inPast90Days,
      valid_until: tomorow
    };
    // bypass addIndicator to have one without decay rules
    indicatorWithoutDecay = await createEntity(testContext, ADMIN_USER, indicatorNoDecayInput, ENTITY_TYPE_INDICATOR);

    const indicatorNoDecayInput2 = {
      name: 'Indicator domain test without decay',
      pattern: '[file:hashes.\'SHA-256\' = \'bbb27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f666\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 92,
      valid_from: inPast90Days,
      valid_until: tomorow
    };
    // bypass addIndicator to have one without decay rules
    indicatorWithoutDecay2 = await createEntity(testContext, ADMIN_USER, indicatorNoDecayInput2, ENTITY_TYPE_INDICATOR);
  });

  afterAll(async () => {
    await stixDomainObjectDelete(testContext, ADMIN_USER, indicatorWithDecay.id);
    await stixDomainObjectDelete(testContext, ADMIN_USER, indicatorWithDecay2.id);
    await stixDomainObjectDelete(testContext, ADMIN_USER, indicatorWithDecay3.id);
    await stixDomainObjectDelete(testContext, ADMIN_USER, indicatorWithoutDecay.id);
    await stixDomainObjectDelete(testContext, ADMIN_USER, indicatorWithoutDecay2.id);
  });

  it('valid until and valid from should be in right order', async () => {
    const futureValidFrom = new Date(new Date(indicatorWithDecay.valid_until).getTime() + dayToMs(1));
    const input: EditInput[] = [{ key: VALID_FROM, value: [futureValidFrom.toUTCString()] }];
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay.id, input)).rejects.toThrowError('The valid until date must be greater than the valid from date');
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithoutDecay.id, input)).rejects.toThrowError('The valid until date must be greater than the valid from date');

    const pastValidUntil = new Date(new Date(indicatorWithDecay.valid_from).getTime() - dayToMs(1));
    const input2: EditInput[] = [{ key: VALID_UNTIL, value: [pastValidUntil.toUTCString()] }];
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay.id, input2)).rejects.toThrowError('The valid until date must be greater than the valid from date');
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithoutDecay.id, input)).rejects.toThrowError('The valid until date must be greater than the valid from date');
  });

  it('On update, input score should be between 0 and 100', async () => {
    const inputBelow: EditInput[] = [{ key: X_SCORE, value: [-12] }];
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay.id, inputBelow)).rejects.toThrowError('The score should be between 0 and 100');
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithoutDecay.id, inputBelow)).rejects.toThrowError('The score should be between 0 and 100');

    const inputAbove: EditInput[] = [{ key: X_SCORE, value: [305] }];
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay.id, inputAbove)).rejects.toThrowError('The score should be between 0 and 100');
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithoutDecay.id, inputAbove)).rejects.toThrowError('The score should be between 0 and 100');

    const inputWeird: EditInput[] = [{ key: X_SCORE, value: ['coucou'] }];
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay.id, inputWeird)).rejects.toThrowError('Attribute must be a numeric/string');
    await expect(() => indicatorEditField(testContext, ADMIN_USER, indicatorWithoutDecay.id, inputWeird)).rejects.toThrowError('Attribute must be a numeric/string');
  });

  it('decay enabled - revoke=true compute new score and new valid until', async () => {
    // --------------------
    // Move revoke to true
    // score should be set to the revoke number
    // indicator should have a valid until date in the past
    const inputToRevoke: EditInput[] = [{ key: 'revoked', value: ['true'] }];
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
    // --------------------
    // Reverse: move revoke to false
    // score should be back to base score
    // indicator should have a valid until date in the future
    const inputToUnrevoke: EditInput[] = [{ key: 'revoked', value: ['false'] }];
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

  it('decay enabled - valid until is moved to past date, indicator should be revoked', async () => {
    const yesterday: Date = new Date(utcDate().toDate().getTime() - dayToMs(1));
    const twoDaysAgo: Date = new Date(utcDate().toDate().getTime() - dayToMs(2));
    const inputToRevoke: EditInput[] = [
      { key: VALID_FROM, value: [twoDaysAgo.toISOString()] },
      { key: VALID_UNTIL, value: [yesterday.toISOString()] }];
    await indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay2.id, inputToRevoke);

    const indicatorValidUntilYesterday = await findById(testContext, ADMIN_USER, indicatorWithDecay2.id);
    expect(indicatorValidUntilYesterday.revoked).toBeTruthy();
    expect(indicatorValidUntilYesterday.x_opencti_score).toBe(indicatorWithDecay2.decay_applied_rule.decay_revoke_score);
    expect(new Date(indicatorValidUntilYesterday.valid_until).getTime()).toBeLessThan(new Date().getTime());
    expect(
      indicatorValidUntilYesterday.decay_history.pop()?.score,
      'The lifecycle history should have a new entry with the score updated'
    ).toBe(indicatorWithDecay2.decay_applied_rule.decay_revoke_score);
  });

  it('no decay - revoke=true compute new score and new valid until', async () => {
    const inputToRevoke: EditInput[] = [{ key: 'revoked', value: [true] }];
    await indicatorEditField(testContext, ADMIN_USER, indicatorWithoutDecay.id, inputToRevoke);

    const indicatorUpdatedRevoked = await findById(testContext, ADMIN_USER, indicatorWithoutDecay.id);
    expect(indicatorUpdatedRevoked.revoked).toBeTruthy();
    expect(indicatorUpdatedRevoked.x_opencti_score).toBe(NO_DECAY_DEFAULT_REVOKED_SCORE);
    expect(new Date(indicatorUpdatedRevoked.valid_until).getTime()).toBeLessThan(new Date().getTime());
  });

  it('no decay - revoke=false compute new score and new valid until', async () => {
    // Reverse: move revoke to false
    const inputToUnrevoke: EditInput[] = [{ key: 'revoked', value: ['false'] }];
    await indicatorEditField(testContext, ADMIN_USER, indicatorWithoutDecay.id, inputToUnrevoke);

    const indicatorUpdatedUnRevoked = await findById(testContext, ADMIN_USER, indicatorWithoutDecay.id);
    expect(indicatorUpdatedUnRevoked.revoked).toBeFalsy();
    expect(indicatorUpdatedUnRevoked.x_opencti_score).toBe(INDICATOR_DEFAULT_SCORE);
    expect(new Date(indicatorUpdatedUnRevoked.valid_until).getTime()).toBeGreaterThan(new Date().getTime());
  });

  it('no decay - valid until is moved to past date, indicator should be revoked', async () => {
    const yesterday: Date = new Date(utcDate().toDate().getTime() - dayToMs(1));
    const twoDaysAgo: Date = new Date(utcDate().toDate().getTime() - dayToMs(2));
    const inputToRevoke: EditInput[] = [
      { key: VALID_FROM, value: [twoDaysAgo.toISOString()] },
      { key: VALID_UNTIL, value: [yesterday.toISOString()] }];
    await indicatorEditField(testContext, ADMIN_USER, indicatorWithoutDecay2.id, inputToRevoke);

    const indicatorValidUntilYesterday = await findById(testContext, ADMIN_USER, indicatorWithoutDecay2.id);
    expect(indicatorValidUntilYesterday.revoked).toBeTruthy();
    expect(indicatorValidUntilYesterday.x_opencti_score).toBe(NO_DECAY_DEFAULT_REVOKED_SCORE);
    expect(new Date(indicatorValidUntilYesterday.valid_until).getTime()).toBeLessThan(new Date().getTime());
  });

  it.only('decay enabled - updating revoke and valid until and score should ??? what', async () => {
    const tomorrow: Date = new Date(utcDate().toDate().getTime() + dayToMs(1));
    const twoDaysAgo: Date = new Date(utcDate().toDate().getTime() - dayToMs(2));
    const inputWithEverything: EditInput[] = [
      { key: VALID_FROM, value: [twoDaysAgo.toISOString()] },
      { key: VALID_UNTIL, value: [tomorrow.toISOString()] },
      { key: X_SCORE, value: [12] },
      { key: 'revoked', value: ['false'] },
    ];
    await indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay3.id, inputWithEverything);

    const indicatorWithAllChanges = await findById(testContext, ADMIN_USER, indicatorWithDecay3.id);
    console.log('indicatorWithAllChanges:', indicatorWithAllChanges);
  });
});
