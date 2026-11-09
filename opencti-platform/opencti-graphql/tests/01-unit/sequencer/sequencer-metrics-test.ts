import { describe, expect, it, vi } from 'vitest';
import { ValueType } from '@opentelemetry/api';
import type { Counter } from '@opentelemetry/api';
import { MeterProvider, MetricReader } from '@opentelemetry/sdk-metrics';
import { PrometheusSerializer } from '@opentelemetry/exporter-prometheus';
import * as tracing from '../../../src/config/tracing';
import { sequencerMetrics, type IntentOutcome, type MapEvent } from '../../../src/database/sequencer/sequencer-metrics';

// Oracle for the hot-path counters kept in plain JS and exported by observable counters: the
// synchronous counters as of b48f3c0250, copied below, fed the same calls, must scrape to the same
// Prometheus text (names, help, type, labels, totals) at every collection.

class TestReader extends MetricReader {
  protected async onShutdown() {}

  protected async onForceFlush() {}
}

vi.mock('../../../src/config/tracing', async () => {
  const sdk = await import('@opentelemetry/sdk-metrics');
  class Reader extends sdk.MetricReader {
    protected async onShutdown() {}

    protected async onForceFlush() {}
  }
  const testReader = new Reader();
  return { meterManager: { meterProvider: new sdk.MeterProvider({ readers: [testReader] }) }, testReader };
});

// ---- reference: the synchronous counters before the rewrite ----
class OldHotCounters {
  private intents: Counter | null = null;

  private identityMap: Counter | null = null;

  register(provider: MeterProvider) {
    const meter = provider.getMeter('opencti-sequencer');
    this.intents = meter.createCounter('opencti_sequencer_intents_total', {
      valueType: ValueType.INT,
      description: 'Intents by outcome (applied, coalesced, parked, expired, failed, bypassed)',
    });
    this.identityMap = meter.createCounter('opencti_sequencer_identity_map', {
      valueType: ValueType.INT,
      description: 'Identity map events (hit, miss, evict, invalidate; absent = served known-absent from the s10.3 batch negative cache, one avoided ES search each)',
    });
  }

  intent(outcome: IntentOutcome, kind?: 'entity' | 'relation') {
    this.intents?.add(1, kind ? { outcome, kind } : { outcome });
  }

  mapEvent(event: MapEvent, count = 1) {
    this.identityMap?.add(count, { event });
  }
}

const HOT = ['opencti_sequencer_intents_total', 'opencti_sequencer_identity_map'];

// the scraped lines of the two hot-path families (the module's other instruments left out)
const scrape = async (reader: MetricReader) => {
  const { resourceMetrics } = await reader.collect();
  resourceMetrics.scopeMetrics.forEach((scope) => {
    scope.metrics = scope.metrics.filter((metric) => HOT.includes(metric.descriptor.name));
  });
  return new PrometheusSerializer().serialize(resourceMetrics).split('\n').filter((line) => HOT.some((name) => line.includes(name)));
};

const lcg = (seed: number) => {
  let s = seed;
  return () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    return s / 0x7fffffff;
  };
};

describe('sequencer hot-path metrics oracle (observable counters)', () => {
  it('should scrape the same names, labels and totals as the synchronous counters', async () => {
    const currentReader = (tracing as any).testReader as MetricReader;
    const oldReader = new TestReader();
    const old = new OldHotCounters();
    old.register(new MeterProvider({ readers: [oldReader] }));
    // nothing recorded yet: no series on either side
    expect(await scrape(currentReader)).toEqual(await scrape(oldReader));
    const outcomes: IntentOutcome[] = ['applied', 'coalesced', 'parked', 'expired', 'failed', 'bypassed', 'deferred', 'retained'];
    const events: MapEvent[] = ['hit', 'miss', 'evict', 'invalidate', 'absent', 'written_hit', 'written_shielded'];
    const kinds = [undefined, 'entity', 'relation'] as const;
    const rnd = lcg(3);
    let lines: string[] = [];
    for (let round = 0; round < 20; round += 1) {
      for (let i = 0; i < 500; i += 1) {
        if (rnd() < 0.5) {
          const outcome = outcomes[Math.floor(rnd() * outcomes.length)];
          const kind = kinds[Math.floor(rnd() * kinds.length)];
          sequencerMetrics.intent(outcome, kind);
          old.intent(outcome, kind);
        } else {
          const event = events[Math.floor(rnd() * events.length)];
          // default count, a bulk count (clear), and the edge counts a counter treats specially
          const count = [undefined, undefined, Math.floor(rnd() * 50), 0, -3][Math.floor(rnd() * 5)];
          sequencerMetrics.mapEvent(event, count);
          old.mapEvent(event, count);
        }
      }
      lines = await scrape(currentReader);
      expect(lines, `round ${round}`).toEqual(await scrape(oldReader));
    }
    // both label shapes of the intents counter, and the map events, were scraped
    expect(lines.some((line) => /^opencti_sequencer_intents_total\{outcome="applied",otel_scope_name="opencti-sequencer"\} \d+$/.test(line))).toBe(true);
    expect(lines.some((line) => /^opencti_sequencer_intents_total\{outcome="applied",kind="entity",otel_scope_name="opencti-sequencer"\} \d+$/.test(line))).toBe(true);
    expect(lines.some((line) => /^opencti_sequencer_identity_map_total\{event="hit",otel_scope_name="opencti-sequencer"\} \d+$/.test(line))).toBe(true);
    expect(lines).toContain('# TYPE opencti_sequencer_identity_map_total counter');
  });
});
