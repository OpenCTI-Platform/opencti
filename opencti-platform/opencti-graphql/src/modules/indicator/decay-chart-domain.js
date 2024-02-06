import moment from 'moment';
import { computeTimeFromExpectedScore } from './decay-domain';
export const dayToMs = (days) => {
    return days * 24 * 60 * 60 * 1000;
};
export const msToDay = (milli) => {
    return milli / 24 / 60 / 60 / 1000;
};
/**
 * Compute all data point (x as time, y as score value) needed to draw the decay mathematical curve as time serie.
 * @param indicator indicator with decay data
 * @param scoreList
 */
export const computeChartDecayAlgoSerie = (indicator, scoreList) => {
    if (indicator.decay_applied_rule && indicator.decay_applied_rule.decay_points && indicator.decay_base_score_date) {
        const decayData = [];
        const startDateInMs = moment(indicator.decay_base_score_date).valueOf();
        scoreList.forEach((scoreValue) => {
            const timeForScore = dayToMs(computeTimeFromExpectedScore(indicator.decay_base_score, scoreValue, indicator.decay_applied_rule));
            const point = { time: moment(startDateInMs + timeForScore).toDate(), score: scoreValue };
            decayData.push(point);
        });
        return decayData;
    }
    return [];
};
/**
 * Compute all time scores needed to draw the chart from base score to 0.
 */
export const computeScoreList = (maxScore) => {
    const scoreArray = [];
    for (let i = maxScore; i >= 0; i -= 1) {
        scoreArray.push(i);
    }
    return scoreArray;
};
