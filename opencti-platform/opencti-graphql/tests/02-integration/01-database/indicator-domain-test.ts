import { afterAll, beforeAll, describe, it, expect } from 'vitest';
import { addIndicator, findById, indicatorEditField } from '../../../src/modules/indicator/indicator-domain';
import type { EditInput, IndicatorAddInput } from '../../../src/generated/graphql';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';
import type { BasicStoreEntityIndicator } from '../../../src/modules/indicator/indicator-types';
import { STIX_PATTERN_TYPE } from '../../../src/utils/syntax';

describe('Testing field patch on indicator for trio {score, valid until, revoked} - manager enabled', () => {
  let indicatorWithDecay: BasicStoreEntityIndicator;
  beforeAll(async () => {
    const indicatorAddInput: IndicatorAddInput = {
      name: 'Indicator domain test with decay',
      pattern: '[file:hashes.\'SHA-256\' = \'4bac27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f877\']',
      pattern_type: STIX_PATTERN_TYPE,
      x_opencti_score: 100,
    };
    indicatorWithDecay = await addIndicator(testContext, ADMIN_USER, indicatorAddInput);
    expect(indicatorWithDecay.revoked).toBeFalsy();
    expect(indicatorWithDecay.decay_applied_rule).toBeDefined();
    expect(indicatorWithDecay.decay_applied_rule.decay_revoke_score).toBeDefined();
    expect(indicatorWithDecay.x_opencti_score).toBeGreaterThan(indicatorWithDecay.decay_applied_rule.decay_revoke_score);
    expect(new Date(indicatorWithDecay.valid_until).getTime()).toBeGreaterThan(new Date().getTime());
    console.log('Indicator with decay:', indicatorWithDecay);
  });

  afterAll(async () => {
    await stixDomainObjectDelete(testContext, ADMIN_USER, indicatorWithDecay.id);
  });

  it('revoke=true compute new score and new valid until', async () => {
    const inputToRevoke: EditInput[] = [{ key: 'revoked', value: [true] }];
    await indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay.id, inputToRevoke);

    const indicatorUpdated1 = await findById(testContext, ADMIN_USER, indicatorWithDecay.id);
    console.log('indicatorUpdated1:', indicatorUpdated1);
    expect(indicatorUpdated1.revoked).toBeTruthy();
    expect(indicatorUpdated1.x_opencti_score).toBe(indicatorWithDecay.decay_applied_rule.decay_revoke_score);
    expect(new Date(indicatorUpdated1.valid_until).getTime()).toBeLessThan(new Date().getTime());

    const inputToUnrevoke: EditInput[] = [{ key: 'revoked', value: [false] }];
    await indicatorEditField(testContext, ADMIN_USER, indicatorWithDecay.id, inputToUnrevoke);

    const indicatorUpdated2 = await findById(testContext, ADMIN_USER, indicatorWithDecay.id);
    expect(indicatorUpdated2.revoked).toBeFalsy();
    expect(indicatorUpdated2.x_opencti_score).toBeGreaterThan(indicatorWithDecay.decay_applied_rule.decay_revoke_score);
    expect(new Date(indicatorUpdated2.valid_until).getTime()).toBeGreaterThan(new Date().getTime());
  });
});
