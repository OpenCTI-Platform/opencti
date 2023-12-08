import { describe, expect, it } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { testContext } from '../../utils/testQuery';
import type { BasicStoreIndicator, DecayModel } from '../../../src/modules/internal/decay/decay-domain';
import {
  computeIndicatorDecayWithModel,
  computeScoreFromExpectedTime,
  computeTimeFromExpectedScore
} from '../../../src/modules/internal/decay/decay-domain';

const basicDecayModel: DecayModel = {
  id: 'STANDARD_MODEL',
  decay_lifetime: 30,
  decay_factor: 3.8,
  decay_pounds: [],
  decay_points: [80, 60, 40, 0],
  decay_revoked_cutoff: 40
};
describe('basic decay testing', () => {
  it('should compute score', () => {
    const baseScore = 100;
    // const time = 30; // days
    const compute20Score = computeScoreFromExpectedTime(baseScore, 20, basicDecayModel);
    expect(Math.round(compute20Score)).toBe(10);
    const compute28Score = computeScoreFromExpectedTime(baseScore, 28, basicDecayModel);
    expect(Math.round(compute28Score)).toBe(2);
    const compute31Score = computeScoreFromExpectedTime(baseScore, 31, basicDecayModel);
    expect(Math.round(compute31Score)).toBe(0);
  });

  it('should compute threshold', () => {
    // Threshold for 40 score
    const baseScore = 100;
    const compute20Score = computeScoreFromExpectedTime(baseScore, 20, basicDecayModel);
    expect(Math.round(computeTimeFromExpectedScore(baseScore, compute20Score, basicDecayModel))).toBe(20);
  });

  it('should compute creation indicator decay', async () => {
    // Try compute
    const indicator = {
      standard_id: `indicator--${uuidv4()}`,
      entity_type: 'Indicator',
      indicator_types: ['abuse', 'apt'],
      x_opencti_score: 100,
      valid_from: new Date('2023-10-18T21:42:54.178Z'),
    } as BasicStoreIndicator;
    const indicatorDecay = await computeIndicatorDecayWithModel(testContext, indicator, basicDecayModel);
    expect(indicatorDecay.decay_base_score).toBe(100);
    expect(indicatorDecay.decay_model_steps.length).toBe(4);
    expect(indicatorDecay.decay_model_steps[0].decay_step_at).toBe('2023-10-18T23:18:16.192Z');
    expect(indicatorDecay.decay_model_steps[0].decay_step_score).toBe(80);
    expect(indicatorDecay.decay_model_steps[1].decay_step_at).toBe('2023-10-19T19:51:15.030Z');
    expect(indicatorDecay.decay_model_steps[1].decay_step_score).toBe(60);
    expect(indicatorDecay.decay_model_steps[2].decay_step_at).toBe('2023-10-23T05:03:51.408Z');
    expect(indicatorDecay.decay_model_steps[2].decay_step_score).toBe(40);
    expect(indicatorDecay.decay_model_steps[3].decay_step_at).toBe('2023-11-17T21:42:54.178Z');
    expect(indicatorDecay.decay_model_steps[3].decay_step_score).toBe(0);
    expect(indicatorDecay.decay_model_steps[3].decay_step_revoked).toBe(true);
  });
});

const poundDecayModel: DecayModel = {
  id: 'POUND_MODEL',
  decay_lifetime: 30,
  decay_factor: 3.8,
  decay_pounds: [
    {
      decay_pound_filters: JSON.stringify(
        { indicator_types: [{ id: 'indicator_types', value: 'invalid' }, { id: 'indicator_types', value: 'apt' }] }
      ),
      decay_pound_factor: 1.5 // Increase decay speed
    }
  ],
  decay_points: [80, 60, 40, 0],
  decay_revoked_cutoff: 40
};
describe('pound decay testing', () => {
  it('should compute creation indicator decay with pound', async () => {
    // Try compute
    const indicator = {
      standard_id: `indicator--${uuidv4()}`,
      entity_type: 'Indicator',
      indicator_types: ['abuse', 'apt'],
      x_opencti_score: 100,
      valid_from: new Date('2023-10-18T21:42:54.178Z'),
    } as BasicStoreIndicator;
    const indicatorDecay = await computeIndicatorDecayWithModel(testContext, indicator, poundDecayModel);
    // console.log(indicatorDecay);
    expect(indicatorDecay.decay_base_score).toBe(100);
    expect(indicatorDecay.decay_model_steps.length).toBe(4);
    expect(indicatorDecay.decay_model_steps[0].decay_step_at).toBe('2023-10-18T21:47:23.025Z');
    expect(indicatorDecay.decay_model_steps[0].decay_step_score).toBe(80);
  });
});
