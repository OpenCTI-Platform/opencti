import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import { MeterProvider } from '@opentelemetry/sdk-metrics';
import { ValueType } from '@opentelemetry/api-metrics';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nodeMetrics from 'opentelemetry-node-metrics';
import { ENABLED_TRACING } from './conf';
class MeterManager {
    constructor(meterProvider) {
        this.requests = null;
        this.errors = null;
        this.latencies = 0;
        this.meterProvider = meterProvider;
    }
    request() {
        var _a;
        (_a = this.requests) === null || _a === void 0 ? void 0 : _a.add(1);
    }
    error() {
        var _a;
        (_a = this.errors) === null || _a === void 0 ? void 0 : _a.add(1);
    }
    latency(val) {
        this.latencies = val;
    }
    registerMetrics() {
        const meter = this.meterProvider.getMeter('opencti-api');
        // Register manual metrics
        // - Basic counters
        this.requests = meter.createCounter('opencti_api_requests', {
            valueType: ValueType.INT,
            description: 'Counts total number of requests'
        });
        this.errors = meter.createCounter('opencti_api_errors', {
            valueType: ValueType.INT,
            description: 'Counts total number of errors'
        });
        // - Gauges
        const latencyGauge = meter.createObservableGauge('opencti_api_latency');
        latencyGauge.addCallback((observableResult) => {
            observableResult.observe(this.latencies);
        });
        // - Library metrics
        nodeMetrics(this.meterProvider, { prefix: '' });
    }
}
export const meterProvider = new MeterProvider({});
export const meterManager = new MeterManager(meterProvider);
export const telemetry = (context, user, spanName, attrs, fn) => {
    // if tracing disabled
    if (!ENABLED_TRACING) {
        return fn();
    }
    // if tracing enabled
    const tracer = context.tracing.getTracer();
    const ctx = context.tracing.getCtx();
    const tracingSpan = tracer.startSpan(spanName, {
        attributes: Object.assign({ 'enduser.type': context.source, [SemanticAttributes.ENDUSER_ID]: user.id }, attrs),
        kind: 2
    }, ctx);
    return fn().then((data) => {
        tracingSpan.setStatus({ code: 1 });
        tracingSpan.end();
        return data;
    }).catch((err) => {
        tracingSpan.setStatus({ code: 2 });
        tracingSpan.end();
        throw err;
    });
};
