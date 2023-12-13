import React, { useState } from 'react';
import { compose } from "ramda";
import inject18n from "../../../../components/i18n";
import { withRouter } from "react-router-dom";
import withStyles from "@mui/styles/withStyles";
import Chart from "react-apexcharts";
import { now } from "moment";
import { Field, Form, Formik } from "formik";
import { FormikValues } from "formik/dist/types";
import {
    computeCutOffSerie,
    computeDecayLiveGraphSerie, computeDecayStableSerie,
    computeXAxisTimeRange,  DecayModel, GraphData
} from "@components/settings/decay/decay-domain";

const styles = () => ({
    container: {
        margin: 0
    },
});

const DEFAULT_DECAY_MODEL: DecayModel = {
    id: 'DEFAULT_DECAY_MODEL',
    decay_lifetime: 30, // 30 days
    decay_factor: 3.0,
    decay_pounds: [], // No specific pounds
    decay_points: [60, 40], // 2 decay points
    decay_revoked_cutoff: 20
};

let graphData: GraphData = {
    timeSerie: [],
    startDateMs:now(),
    startScore:100,
    decayModel: DEFAULT_DECAY_MODEL,
    pointCount: 150,
    pound: 1
};

export const handleSubmit = (values: FormikValues) => {
    const newStartScore: number = parseInt(values.startScore);
    if (newStartScore > 0 && newStartScore <=100 ) {
        graphData.startScore = newStartScore;
    }

    const newPound: number = parseFloat(values.pound);
    if (newPound) {
        graphData.pound = newPound;
    }

    const newLifeTime: number = parseInt(values.lifetime);
    if (newLifeTime > 0) {
        graphData.decayModel.decay_lifetime = newLifeTime;
    }

    if (values.reactionPoints) {
        graphData.decayModel.decay_points = values.reactionPoints.split(';');
    }

    const newCutOff: number = parseInt(values.cutoff);
    if (newCutOff) {
        graphData.decayModel.decay_revoked_cutoff = newCutOff;
    }
}
const Decay = () => {

    const [refreshMeNow, setRefreshMeNow] = useState(true);

    graphData.timeSerie = computeXAxisTimeRange(graphData);

    const series = [{ name: "Live score", data:computeDecayLiveGraphSerie(graphData), type: 'line'}]
    series.push({ name: "Trigger point", data:computeDecayStableSerie(graphData), type: 'column'});
    series.push({ name: "Cut Off", data:computeCutOffSerie(graphData), type: 'column'});

    const chartOptions= {
        chart: {id: 'Decay graph'},
        xaxis: { type: 'datetime'},
        yaxis: {min: 0,max: 100}};

    return (
        <div>
        <span>This page is a POC for decay formula.</span>
            <div className="app">
                <div className="row">
                    <div className="mixed-chart">
                        <Chart
                            series={series}
                            options={chartOptions}
                            type="line"
                            width="500"/>
                    </div>
                    <div>
                        <Formik
                            initialValues={{
                                startScore: '100',
                                pound: '1',
                                lifetime: '30',
                                reactionPoints:'80;40;20',
                                cutoff: 20
                            }}
                            onSubmit={async (values) => {
                                handleSubmit(values);
                                setRefreshMeNow(!refreshMeNow);
                            }}
                        >
                            <Form>
                                <div>
                                    <label htmlFor="startScore">Start score (100-0):</label>
                                    <Field id="startScore" name="startScore"/>
                                </div>

                                <div>
                                    <label htmlFor="pound">Pound (ex: 0.8):</label>
                                    <Field id="pound" name="pound" />
                                </div>

                                <div>
                                    <label htmlFor="lifetime">Lifetime in days (ex: 30):</label>
                                    <Field id="lifetime" name="lifetime"/>
                                </div>

                                <div>
                                    <label htmlFor="reactionPoints">List of reaction point (ex: 80;40;20):</label>
                                    <Field id="reactionPoints" name="reactionPoints"/>
                                </div>

                                <div>
                                    <label htmlFor="cutoff">Cut-Off score (ex: 20):</label>
                                    <Field id="cutoff" name="cutoff"/>
                                </div>

                                <div>
                                    <button type="submit">Submit</button>
                                </div>
                            </Form>
                        </Formik>
                    </div>
                    <div>
                        <div>Model is:- </div>
                        <div>decay_factor: {graphData.decayModel.decay_factor}</div>
                        <div>decay_lifetime: {graphData.decayModel.decay_lifetime} day(s)</div>
                        <div>decay_revoked_cutoff: {graphData.decayModel.decay_revoked_cutoff} day(s)</div>
                    </div>
                </div>
            </div>
        </div>
);
}

export default compose(inject18n, withRouter, withStyles(styles))(Decay);