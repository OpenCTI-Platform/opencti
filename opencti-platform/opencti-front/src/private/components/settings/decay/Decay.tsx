import React from 'react';
import { compose } from "ramda";
import inject18n from "../../../../components/i18n";
import { withRouter } from "react-router-dom";
import withStyles from "@mui/styles/withStyles";
import Chart from "react-apexcharts";
import { now } from "moment";

const styles = () => ({
    container: {
        margin: 0
    },
});
interface DecayPound {
    decay_pound_filters: string
    decay_pound_factor: number
}

interface Point {
    x: number
    y: number
}
export interface DecayModel {
    id: string
    decay_lifetime: number
    decay_factor: number
    decay_pounds: DecayPound[]
    decay_points: number[]
    decay_revoked_cutoff: number
}

const DEFAULT_DECAY_MODEL: DecayModel = {
    id: 'DEFAULT_DECAY_MODEL',
    decay_lifetime: 30, // 30 days
    decay_factor: 3.0,
    decay_pounds: [], // No specific pounds
    decay_points: [60, 40], // 2 decay points
    decay_revoked_cutoff: 40,
    // decay_apply_on: // filters
};

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

const Decay = () => {
    const chartOptions= { chart: {id: 'basic-bar'}, xaxis: {categories: ['1991', '1992', '1993', '1994', '1995', '1996', '1997', '1998', '1999']}};
    //const series= [{ name: "series-1",data: [30, 40, 45, 50, 49, 60, 70, 91]}];

    const decayScores = [100, 90, 80, 70, 60, 50, 40, 30, 20, 10, 0];
    const decayData: number[][] = [];
    decayScores.forEach(function (score) {
        const point: [number, number] = [ Math.round(computeTimeFromExpectedScore(100, score, DEFAULT_DECAY_MODEL, 1)), score];
        decayData.push(point);
    });
    const series = [{ name: "series-1",data:decayData}];
    console.log('decayDates', decayData);
    console.log('decayScores', decayScores);
    return (
        <div>
        <span>Coucou</span>
            <div className="app">
                <div className="row">
                    <div className="mixed-chart">
                        <Chart
                            options={chartOptions}
                            series={series}
                            type="line"
                            width="500"/>
                    </div>
                </div>
            </div>
        </div>
);
}

export default compose(inject18n, withRouter, withStyles(styles))(Decay);