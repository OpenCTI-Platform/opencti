import moment from 'moment';
import type { BasicStoreEntityIndicator } from './indicator-types';
import { computeTimeFromExpectedScore, type DecayRule } from './decay-domain';

export const dayToMs = (days: number) => {
  return days * 24 * 60 * 60 * 1000;
};

export const msToDay = (milli: number) => {
  return milli / 24 / 60 / 60 / 1000;
};

export interface DecayPoint {
  time: Date,
  score: number,
}
export interface DecayChartData {
  live_score_serie: DecayPoint[]
}

/**
 * Compute all data point (x as time, y as score value) needed to draw the decay mathematical curve as time serie.
 * @param indicator indicator with decay data
 * @param scoreList
 */
export const computeChartDecayAlgoSerie = (indicator: BasicStoreEntityIndicator, scoreList: number[]): DecayPoint[] => {
  if (indicator.decay_applied_rule && indicator.decay_applied_rule.decay_points && indicator.decay_base_score_date) {
    const decayData: DecayPoint[] = [];
    const startDateInMs = moment(indicator.decay_base_score_date).valueOf();
    scoreList.forEach((scoreValue) => {
      const timeForScore = dayToMs(computeTimeFromExpectedScore(indicator.decay_base_score, scoreValue, indicator.decay_applied_rule as DecayRule));
      const point: DecayPoint = { time: moment(startDateInMs + timeForScore).toDate(), score: scoreValue };
      decayData.push(point);
    });
    return decayData;
  }
  return [];
};

/**
 * Compute all time scores needed to draw the chart from base score to 0.
 */
export const computScoreList = (maxScore:number): number[] => {
  const scoreArray: number[] = [];
  for (let i = maxScore; i >= 0; i -= 1) {
    scoreArray.push(i);
  }
  return scoreArray;
};
