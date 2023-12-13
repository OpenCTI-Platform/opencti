import { now } from "moment/moment";

export interface GraphData {
    timeSerie: number[],
    startDateMs: number,
    startScore: number,
    decayModel: DecayModel,
    pointCount: number,
    pound: number
}

export interface DecayPound {
    decay_pound_filters: string
    decay_pound_factor: number
}

export interface DecayModel {
    id: string
    decay_lifetime: number
    decay_factor: number
    decay_pounds: DecayPound[]
    decay_points: number[]
    decay_revoked_cutoff: number
}
export const computeDecayLiveGraphSerie = (graphData: GraphData) => {
    const decayData: number[][] = [];
    graphData.timeSerie.forEach(function (timeStep) {
        const scoreAtTime = computeScoreFromExpectedTime(graphData.startScore,MsToDay(timeStep - graphData.startDateMs), graphData.decayModel, graphData.pound);
        const point: [number, number] = [ timeStep, Math.round(scoreAtTime)];
        decayData.push(point);
    });
    return decayData;
}

export const computeScoreFromExpectedTime = (initialAmount: number, after: number, model: DecayModel, pound: number = 1) => {
    // Polynomial implementation (MISP approach)
    if (after > model.decay_lifetime) return 0;
    if (after <= 0) return initialAmount;
    return initialAmount * (1 - ((after / model.decay_lifetime) ** (1 / (model.decay_factor * pound))));
};

export const computeTimeFromExpectedScore = (initialAmount: number, score: number, model: DecayModel, pound: number = 1) => {
    // Polynomial implementation (MISP approach)
    return (Math.E ** (Math.log(1 - (score / initialAmount)) * (model.decay_factor * pound))) * model.decay_lifetime;
};

export const computeXAxisTimeRange = (graphData: GraphData): number[] => {
    const endDate = graphData.startDateMs + dayToMs(graphData.decayModel.decay_lifetime);
    const steps = (endDate - graphData.startDateMs)/graphData.pointCount;
    const timeArray: number[] = [];
    for (let i = 0; i < graphData.pointCount; i++) {
        timeArray.push(graphData.startDateMs + i * steps);
    }
    return timeArray;
}

export const computeDecayStableSerie = (graphData: GraphData) => {
    const decayHotPoint: number[][] = [];
    graphData.decayModel.decay_points.forEach(function (stableScore) {
        const timeForHotPoint = computeTimeFromExpectedScore(graphData.startScore, stableScore, graphData.decayModel, graphData.pound);
        const hotPoint: [number, number] = [ graphData.startDateMs + dayToMs(timeForHotPoint), stableScore];
        decayHotPoint.push(hotPoint);
    });
    return decayHotPoint;
}

export const computeCutOffSerie = (graphData: GraphData) => {
    const decayCutOffPoint: number[][] = [];
    const timeForCutOffPoint = computeTimeFromExpectedScore(graphData.startScore, graphData.decayModel.decay_revoked_cutoff, graphData.decayModel, graphData.pound);
    const timeForGraph: number = graphData.startDateMs + dayToMs(timeForCutOffPoint);
    decayCutOffPoint.push([timeForGraph, graphData.decayModel.decay_revoked_cutoff]);
    return decayCutOffPoint;
}

export const dayToMs = (days: number) => {
    return days*24*60*60*1000;
}

export const MsToDay = (milli: number) => {
    return milli/24/60/60/1000;
}