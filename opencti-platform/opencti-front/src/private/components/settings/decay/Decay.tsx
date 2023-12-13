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
    pointCount: 30,
    pound: 1
};

export const handleSubmit = (values: FormikValues) => {
    console.log('handleSubmit of ', values);
    const newStartScore: number = parseInt(values.startScore);
    if (newStartScore > 0 && newStartScore <=100 ) {
        graphData.startScore = newStartScore;
    }

    const newPound: number = parseFloat(values.pound);
    if (newPound) {
        graphData.pound = newPound;
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
                                startScore: '',
                                pound: '',
                            }}
                            onSubmit={async (values) => {
                                handleSubmit(values);
                                setRefreshMeNow(!refreshMeNow);
                            }}
                        >
                            <Form>
                                <label htmlFor="startScore">Start score (100-0)</label>
                                <Field id="startScore" name="startScore" placeholder="100" />

                                <label htmlFor="pound">Pound (ex: 1)</label>
                                <Field id="pound" name="pound" placeholder="1" />
                                <button type="submit">Submit</button>
                            </Form>
                        </Formik>
                    </div>
                    <div>
                        <div>Model is:- </div>
                        <div>decay_points: {graphData.decayModel.decay_points}</div>
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