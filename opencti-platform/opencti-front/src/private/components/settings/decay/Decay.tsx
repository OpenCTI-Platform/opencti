import React, { useState } from 'react';
import Chart from "react-apexcharts";
import { now } from "moment";
import { Field, Form, Formik } from "formik";
import { FormikValues } from "formik/dist/types";
import {
    computeCutOffSerie,
    computeDecayLiveGraphSerie, computeDecayStableSerie,
    computeXAxisTimeRange,  DecayModel, GraphData
} from "@components/settings/decay/decay-domain";
import { ApexOptions } from "apexcharts";

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

    const newFactor: number = parseInt(values.factor);
    if (newFactor) {
        graphData.decayModel.decay_factor = newFactor;
    }

    const newPointCount: number = parseInt(values.pointcount);
    if (newPointCount>0) {
        graphData.pointCount = values.pointcount;
    }
}
const Decay = () => {

    const [refreshMeNow, setRefreshMeNow] = useState(true);

    graphData.timeSerie = computeXAxisTimeRange(graphData);

    const series = [{ name: "Live score", data:computeDecayLiveGraphSerie(graphData), type: 'line'}]
    series.push({ name: "Trigger point", data:computeDecayStableSerie(graphData), type: 'column'});
    series.push({ name: "Revoke score", data:computeCutOffSerie(graphData), type: 'column'});

    const chartOptions: ApexOptions= {
        chart: {id: 'Decay graph'},
        xaxis: { type: 'datetime'},
        yaxis: {min: 0,max: 100}
    };

    return (
        <div>
        <span>This page is a POC for decay formula.</span>
            <div>
                <div>
                    <div>
                        <Chart
                            series={series}
                            options={chartOptions}
                            type="line"
                            width="500"/>
                    </div>
                    <div>
                        <Formik
                            initialValues={{
                                startScore: graphData.startScore,
                                pound: graphData.pound,
                                lifetime: graphData.decayModel.decay_lifetime,
                                reactionPoints:'60;40',
                                cutoff: graphData.decayModel.decay_revoked_cutoff,
                                factor: graphData.decayModel.decay_factor,
                                pointcount: graphData.pointCount
                            }}
                            onSubmit={async (values) => {
                                handleSubmit(values);
                                setRefreshMeNow(!refreshMeNow);
                            }}
                        >
                            <Form>
                                <div>
                                    <button type="submit">Update graph</button>
                                </div>

                                <h3>From Indicator data</h3>
                                <div>
                                    <label htmlFor="startScore">Start score (100-0):</label>
                                    <Field id="startScore" name="startScore"/>
                                </div>

                                <h3>Can be customized in Settings</h3>
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
                                    <label htmlFor="cutoff">Revoke score (ex: 20):</label>
                                    <Field id="cutoff" name="cutoff"/>
                                </div>

                                <h3>Hardcoded (or system parameter)</h3>
                                <div>
                                    <label htmlFor="factor">Decay factor (ex: 3):</label>
                                    <Field id="factor" name="factor"/>
                                </div>
                                <div>
                                    <label htmlFor="pointcount">Point count to draw the blue line:</label>
                                    <Field id="pointcount" name="pointcount"/>
                                </div>
                            </Form>
                        </Formik>
                    </div>
                    <div>
                        <h3>Model is:- </h3>
                        <div>decay_factor: {graphData.decayModel.decay_factor}</div>
                        <div>decay_lifetime: {graphData.decayModel.decay_lifetime} day(s)</div>
                        <div>decay_revoked_cutoff: {graphData.decayModel.decay_revoked_cutoff} day(s)</div>
                        <h3></h3>
                        <div>point count: {graphData.pointCount} points</div>
                    </div>
                </div>
            </div>
        </div>
);
}
export default Decay;