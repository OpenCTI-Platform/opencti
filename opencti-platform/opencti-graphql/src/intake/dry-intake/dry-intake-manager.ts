import amqp from 'amqplib/callback_api';
import { type IntervalHistogram, monitorEventLoopDelay } from 'node:perf_hooks';
import { ValueType } from '@opentelemetry/api';
import conf, { ENABLED_METRICS, logApp } from '../../config/conf';
import { meterManager } from '../../config/tracing';
import { rabbitmqConnectionOptions, rabbitmqUri } from '../../database/rabbitmq';
import createSchema from '../../graphql/schema';
import { connectorsForWorker } from '../../modules/connector/connector-domain';
import { getVocabulariesCategories } from '../../modules/vocabulary/vocabulary-utils';
import { executionContext, SYSTEM_USER } from '../../utils/access';
import { createImportContext, type ImportContext } from '../stix-import/context';
import type { ImportLogger } from '../stix-import/types';
import { DryClient } from './dry-client';
import { type DryAnswer, type DryChannel, createDryDrain } from './dry-intake-drain';
import { DRY_RUNGS, type DryMessageResult, type DryRung, processDryMessage } from './dry-intake-message';

// Bench only. The platform consumes the connector push queues in place of the workers and runs
// each message up to a rung (dry-intake-message.ts) WITHOUT WRITING ANYTHING, then acks it: the
// messages are lost. Never enable it on a platform holding data you need.
// - not a cluster singleton: every node that enables it consumes;
// - the queues are those of the workers (connectorsForWorker), read once at start: fill them
//   first, then start the platform with the manager enabled;
// - one message at a time, yielding between messages (dry-intake-drain.ts), so the stage timings
//   are costs, not overlaps; the prefetch only sizes the broker buffer, per queue (messages in
//   flight = queues x prefetch);
// - no yield inside a message, on purpose: the bench measures what the transformation of a whole
//   bundle costs the main thread (event loop lag and CPU) to decide where it should run (task 0040,
//   thread placement); a message longer than SLOW_MESSAGE_SECONDS is logged, it risks the broker
//   heartbeat (the connection drops, the message is redelivered);
// - one channel per queue, as the worker has one connection per queue: a queue that fails (missing,
//   deleted) stops only its own consumer;
// - the CPU, RSS and event loop gauges are measured in process at each answer (short windows),
//   see createMetrics; the metrics must be enabled, or nothing is measured;
// - one transformation context per draft, kept for the life of the process, as the worker keeps
//   its pycti caches.

const LOG_PREFIX = '[OPENCTI-MODULE] Dry intake manager:';
const RETRY_CONNECTION_PERIOD = 10000;
const SLOW_MESSAGE_SECONDS = 30;
// AMQP prefetch count is an unsigned 16-bit value; setTimeout takes at most a signed 32-bit delay
const MAX_PREFETCH = 65535;
const MAX_START_DELAY_S = (2 ** 31 - 1) / 1000;

export interface DryIntakeOptions {
  rung: unknown;
  // Unacked messages per queue
  prefetch: unknown;
  // Seconds between the start of the manager and the first consumption, so the first messages do
  // not share the CPU with the start of the other managers
  startDelayS: unknown;
  metricsEnabled: boolean;
}

const configuredOptions = (): DryIntakeOptions => ({
  rung: conf.get('dry_intake_manager:rung'),
  prefetch: conf.get('dry_intake_manager:prefetch') ?? 10,
  startDelayS: conf.get('dry_intake_manager:start_delay_s') ?? 0,
  metricsEnabled: ENABLED_METRICS,
});

// Why the manager cannot start with these options, null when it can
export const dryIntakeOptionsError = (options: DryIntakeOptions): string | null => {
  if (!DRY_RUNGS.includes(options.rung as DryRung)) {
    return `dry_intake_manager:rung must be one of ${DRY_RUNGS.join(', ')}`;
  }
  // Prefetch 0 is no limit in AMQP: the broker would push whole queues into memory
  if (!Number.isInteger(options.prefetch) || (options.prefetch as number) < 1 || (options.prefetch as number) > MAX_PREFETCH) {
    return `dry_intake_manager:prefetch must be an integer from 1 to ${MAX_PREFETCH}`;
  }
  if (typeof options.startDelayS !== 'number' || !Number.isFinite(options.startDelayS) || options.startDelayS < 0 || options.startDelayS > MAX_START_DELAY_S) {
    return `dry_intake_manager:start_delay_s must be a number of seconds from 0 to ${MAX_START_DELAY_S}`;
  }
  // The messages are acked without being written: without metrics, the run measures nothing
  if (!options.metricsEnabled) {
    return 'app:telemetry:metrics:enabled must be true';
  }
  return null;
};

const STAGE_BUCKETS = [0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30];
const OBJECT_BUCKETS = [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 50000];

// The measure window, from the start of the first message to the last answer: the CPU, RSS and
// event loop gauges are snapshots taken at each answer, so the idle time after the last answer
// does not dilute them
export interface DryWindow {
  // Start of the handling of the first message: the window, the CPU and the lag start there
  firstStart: number | null;
  lastAck: number | null;
  // Process CPU at the first start, and the CPU seconds used from the first start to the last ack
  cpuAtFirstStart: NodeJS.CpuUsage | null;
  cpuSeconds: number | null;
  rssMax: number | null;
  // Event loop delay from the first start to the last ack, in seconds
  lagP99: number | null;
  lagMax: number | null;
}

export interface DryWindowProbes {
  // Seconds
  now: () => number;
  cpuUsage: (previous?: NodeJS.CpuUsage) => NodeJS.CpuUsage;
  rss: () => number;
  lag: Pick<IntervalHistogram, 'reset' | 'percentile' | 'max'>;
}

export const createDryWindow = (probes: DryWindowProbes) => {
  const window: DryWindow = { firstStart: null, lastAck: null, cpuAtFirstStart: null, cpuSeconds: null, rssMax: null, lagP99: null, lagMax: null };
  let messageStart = 0;
  return {
    window,
    start: () => {
      messageStart = probes.now();
      if (window.firstStart === null) {
        window.firstStart = messageStart;
        window.cpuAtFirstStart = probes.cpuUsage();
        probes.lag.reset();
      }
    },
    // A dropped message is redelivered and handled again: it does not end the window. Gives the
    // seconds the message took
    answer: (answer: DryAnswer) => {
      const now = probes.now();
      if (answer !== 'dropped') {
        window.lastAck = now;
        const cpu = probes.cpuUsage(window.cpuAtFirstStart ?? undefined);
        window.cpuSeconds = (cpu.user + cpu.system) / 1e6;
        window.rssMax = Math.max(window.rssMax ?? 0, probes.rss());
        window.lagP99 = probes.lag.percentile(99) / 1e9;
        window.lagMax = probes.lag.max / 1e9;
      }
      return now - messageStart;
    },
  };
};

interface DryIntakeState {
  pending: number;
  queues: number;
  window: DryWindow;
}

const createMetrics = (state: DryIntakeState) => {
  const meter = meterManager.meterProvider.getMeter('opencti-dry-intake');
  const metrics = {
    messages: meter.createCounter('opencti_dry_intake_messages', { valueType: ValueType.INT, description: 'Messages of the dry intake, per rung and result (acked, nacked; dropped: channel closed before the answer, handled or still pending, redelivered by the broker)' }),
    defects: meter.createCounter('opencti_dry_intake_defects', { valueType: ValueType.INT, description: 'Messages whose transformation raised a native error (a defect of the port)' }),
    objects: meter.createCounter('opencti_dry_intake_objects', { valueType: ValueType.INT, description: 'STIX objects of the bundles received (before any split), per rung' }),
    parts: meter.createCounter('opencti_dry_intake_split_parts', { valueType: ValueType.INT, description: 'Bundles the split gives (split rung, multi-object bundles)' }),
    outcomes: meter.createCounter('opencti_dry_intake_object_outcomes', { valueType: ValueType.INT, description: 'Per object outcome, per rung (transformed, a Python error name, set_aside)' }),
    operations: meter.createCounter('opencti_dry_intake_operations', { valueType: ValueType.INT, description: 'GraphQL operations built by the transformation' }),
    logs: meter.createCounter('opencti_dry_intake_object_logs', { valueType: ValueType.INT, description: 'Logs of the transformation, per level' }),
    stage: meter.createHistogram('opencti_dry_intake_stage_seconds', { valueType: ValueType.DOUBLE, description: 'Time spent per stage and message', advice: { explicitBucketBoundaries: STAGE_BUCKETS } }),
    messageObjects: meter.createHistogram('opencti_dry_intake_message_objects', { valueType: ValueType.INT, description: 'STIX objects per message', advice: { explicitBucketBoundaries: OBJECT_BUCKETS } }),
  };
  const gauge = (name: string, description: string, value: () => number | null) => {
    meter.createObservableGauge(name, { valueType: ValueType.DOUBLE, description }).addCallback((result) => {
      const current = value();
      if (current !== null) {
        result.observe(current);
      }
    });
  };
  gauge('opencti_dry_intake_pending_messages', 'Messages received and not yet handled', () => state.pending);
  gauge('opencti_dry_intake_queues', 'Push queues consumed (live consumers)', () => state.queues);
  gauge('opencti_dry_intake_first_start_timestamp_seconds', 'Time the first message started to be handled (the window starts there)', () => state.window.firstStart);
  gauge('opencti_dry_intake_last_ack_timestamp_seconds', 'Time of the last ack', () => state.window.lastAck);
  // From the first start to the last ack, unlike nodejs_eventloop_lag_* which covers the whole process
  // life: a snapshot at each answer, so the idle time after the last ack does not dilute it
  gauge('opencti_dry_intake_eventloop_lag_p99_seconds', 'Event loop delay p99 from the first start to the last ack', () => state.window.lagP99);
  gauge('opencti_dry_intake_eventloop_lag_max_seconds', 'Event loop delay max from the first start to the last ack', () => state.window.lagMax);
  // Measured in process at each ack: the windows of a dry run are too short for a scraped CPU rate
  gauge('opencti_dry_intake_cpu_seconds', 'Process CPU seconds (user + system) from the first start to the last ack', () => state.window.cpuSeconds);
  gauge('opencti_dry_intake_rss_max_bytes', 'Max resident set size seen at an ack', () => state.window.rssMax);
  return metrics;
};

type DryIntakeMetrics = Pick<ReturnType<typeof createMetrics>, 'messages' | 'defects' | 'objects' | 'parts' | 'operations' | 'outcomes' | 'stage' | 'messageObjects'>;

// A dropped message is redelivered and counted then: only the drop is counted here
export const recordResult = (metrics: DryIntakeMetrics, rung: DryRung, result: DryMessageResult, answer: DryAnswer) => {
  metrics.messages.add(1, { rung, result: answer });
  if (answer === 'dropped') {
    return;
  }
  if (result.defect) {
    metrics.defects.add(1, { rung });
  }
  metrics.objects.add(result.objects, { rung });
  metrics.parts.add(result.parts, { rung });
  metrics.operations.add(result.operations, { rung });
  Object.entries(result.outcomes).forEach(([outcome, count]) => metrics.outcomes.add(count, { rung, outcome }));
  Object.entries(result.timings).forEach(([stage, value]) => metrics.stage.record(value, { stage }));
  // A message refused before its objects are read (ack rung, decode failure) has no object count
  if (result.objects > 0) {
    metrics.messageObjects.record(result.objects, { rung });
  }
};

export const initDryIntakeManager = (options: DryIntakeOptions = configuredOptions()) => {
  const lag = monitorEventLoopDelay({ resolution: 10 });
  const measure = createDryWindow({ now: () => Date.now() / 1000, cpuUsage: (previous) => process.cpuUsage(previous), rss: () => process.memoryUsage.rss(), lag });
  const state: DryIntakeState = { pending: 0, queues: 0, window: measure.window };
  const openChannels = new Set<amqp.Channel>();
  // The queue of each channel, for the logs
  const channelQueues = new Map<amqp.Channel, string>();
  let connection: amqp.Connection | null = null;
  let stopping = false;
  let deps: Parameters<typeof processDryMessage>[1];
  let metrics: ReturnType<typeof createMetrics>;
  let defects = 0;

  const drain = createDryDrain<amqp.Message>({
    body: (message) => message.content.toString(),
    handle: (body) => processDryMessage(body, deps),
    isOpen: (channel) => openChannels.has(channel as amqp.Channel),
    stopping: () => stopping,
    onStart: () => {
      state.pending = drain.pending();
      measure.start();
    },
    onAnswer: (result, answer, channel) => {
      const messageSeconds = measure.answer(answer);
      recordResult(metrics, deps.rung, result, answer);
      const queue = channelQueues.get(channel as amqp.Channel);
      if (messageSeconds > SLOW_MESSAGE_SECONDS) {
        logApp.warn(`${LOG_PREFIX} slow message, the broker heartbeat may drop the connection`, { queue, seconds: messageSeconds });
      }
      if (result.defect) {
        // The defects counter carries the volume: a record for the first defect, then one per hundred
        defects += 1;
        if (defects % 100 === 1) {
          logApp.warn(`${LOG_PREFIX} transformation defect`, { queue, defects });
        }
      }
    },
    onError: (cause) => logApp.warn(`${LOG_PREFIX} message handling failed`, { cause }),
  });

  const closeChannel = (channel: amqp.Channel) => {
    openChannels.delete(channel);
    state.queues = openChannels.size;
    const forgotten = drain.forget(channel);
    if (forgotten > 0) {
      metrics.messages.add(forgotten, { rung: deps.rung, result: 'dropped' });
    }
    state.pending = drain.pending();
  };

  const consumeQueue = (openedConnection: amqp.Connection, queue: string, prefetch: number) => {
    openedConnection.createChannel((channelError, channel) => {
      if (channelError) {
        logApp.warn(`${LOG_PREFIX} cannot open a channel, queue not consumed`, { queue, cause: channelError });
        return;
      }
      openChannels.add(channel);
      channelQueues.set(channel, queue);
      state.queues = openChannels.size;
      // A refused consumption (missing queue...) closes the channel with an error: one record per queue
      channel.on('error', (cause) => logApp.warn(`${LOG_PREFIX} channel error, queue no longer consumed`, { queue, cause }));
      channel.on('close', () => closeChannel(channel));
      // Per consumer (global = false): the queue holds at most `prefetch` unacked messages
      channel.prefetch(prefetch, false);
      channel.consume(queue, (message) => {
        if (message === null) {
          // Cancelled by the broker (queue deleted): the channel would stay open, holding its unacked
          // deliveries; closed, its close event forgets them and the broker redelivers them
          logApp.warn(`${LOG_PREFIX} consumption cancelled by the broker, queue no longer consumed`, { queue });
          try {
            channel.close(() => {});
          } catch {
            closeChannel(channel);
          }
          return;
        }
        drain.push(message, channel as DryChannel<amqp.Message>).catch((cause) => logApp.error(`${LOG_PREFIX} drain failed`, { cause }));
        state.pending = drain.pending();
      }, { noAck: false });
    });
  };

  const consume = (queues: string[], prefetch: number) => {
    amqp.connect(rabbitmqUri(), rabbitmqConnectionOptions(), (error, openedConnection) => {
      const retry = (cause: unknown) => {
        logApp.warn(`${LOG_PREFIX} connection lost, retrying`, { cause });
        connection = null;
        if (!stopping) {
          setTimeout(() => {
            if (!stopping) {
              consume(queues, prefetch);
            }
          }, RETRY_CONNECTION_PERIOD);
        }
      };
      if (error) {
        retry(error);
        return;
      }
      // Opened while the platform stops: nothing to consume
      if (stopping) {
        openedConnection.close();
        return;
      }
      connection = openedConnection;
      openedConnection.on('error', (cause) => logApp.warn(`${LOG_PREFIX} connection error`, { cause }));
      openedConnection.on('close', () => !stopping && retry(new Error('connection closed')));
      queues.forEach((queue) => consumeQueue(openedConnection, queue, prefetch));
      logApp.info(`${LOG_PREFIX} consuming`, { queues: queues.length, prefetch, rung: deps.rung });
    });
  };

  return {
    start: async () => {
      const optionsError = dryIntakeOptionsError(options);
      if (optionsError) {
        logApp.error(`${LOG_PREFIX} not started, ${optionsError}`, { rung: options.rung, prefetch: options.prefetch, start_delay_s: options.startDelayS });
        return false;
      }
      const rung = options.rung as DryRung;
      const prefetch = options.prefetch as number;
      const startDelayS = options.startDelayS as number;
      logApp.info(`${LOG_PREFIX} starting, push messages are acked WITHOUT BEING WRITTEN, they are lost (bench only)`, { rung });
      const context = executionContext('dry_intake_manager');
      // One consumer per queue, as the worker: connectorsForWorker lists some queues twice (background tasks)
      const queues = [...new Set((await connectorsForWorker(context, SYSTEM_USER)).map((connector) => connector.config?.push).filter((queue) => typeof queue === 'string'))];
      const client = new DryClient({ vocabularyCategories: getVocabulariesCategories() }, rung === 'validate' ? createSchema() : null);
      const logs: ImportLogger = {
        error: () => metrics.logs.add(1, { level: 'error' }),
        warn: () => metrics.logs.add(1, { level: 'warn' }),
      };
      const contexts = new Map<string, ImportContext>();
      const contextFor = (draftId: string) => {
        let draftContext = contexts.get(draftId);
        if (!draftContext) {
          draftContext = createImportContext(client, logs, { draftId });
          contexts.set(draftId, draftContext);
        }
        return draftContext;
      };
      deps = { rung, client, contextFor };
      metrics = createMetrics(state);
      lag.enable();
      if (startDelayS > 0) {
        logApp.info(`${LOG_PREFIX} consumption starts in ${startDelayS}s`);
      }
      setTimeout(() => {
        if (!stopping) {
          consume(queues, prefetch);
        }
      }, startDelayS * 1000);
      return true;
    },
    shutdown: async () => {
      stopping = true;
      lag.disable();
      try {
        connection?.close();
      } catch {
        // Already closed
      }
      return true;
    },
  };
};

const dryIntakeManager = initDryIntakeManager();

export default dryIntakeManager;
