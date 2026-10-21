import type { Context } from '@opentelemetry/api';
import type { LogRecordProcessor, ReadWriteLogRecord, ForceFlushOptions } from '@opentelemetry/sdk-logs';

export const RECORDS_SUPPRESSED_EVENT_NAME = 'opencti.frontend.records_suppressed';

const DEFAULT_WINDOW_MILLIS = 60_000;
const DEFAULT_MAX_TRACKED_KEYS = 500;

export interface SuppressedRecords {
  eventName: string;
  level: string;
  count: number;
}

export interface DedupLogRecordProcessorOptions {
  windowMillis?: number;
  maxTrackedKeys?: number;
  onSuppressed?: (suppressed: SuppressedRecords) => void;
  now?: () => number;
}

interface DedupWindow {
  openedAt: number;
  suppressed: number;
  eventName: string;
  level: string;
}

// No stacktrace, so the same error thrown from different places still groups.
const recordKey = (record: ReadWriteLogRecord) => {
  const attributes = record.attributes ?? {};
  return [
    record.severityText ?? '',
    record.eventName ?? '',
    String(record.body ?? ''),
    String(attributes['exception.type'] ?? ''),
    String(attributes['exception.message'] ?? ''),
  ].join('|');
};

// The SDK calls every registered processor for every record, so a processor cannot
// drop a record for its peers. This one wraps the downstream processor and forwards
// only what survives deduplication: register this one, not the one it delegates to.
export class DedupLogRecordProcessor implements LogRecordProcessor {
  private readonly windows = new Map<string, DedupWindow>();

  private readonly windowMillis: number;

  private readonly maxTrackedKeys: number;

  private readonly onSuppressed?: (suppressed: SuppressedRecords) => void;

  private readonly now: () => number;

  constructor(
    private readonly delegate: LogRecordProcessor,
    options: DedupLogRecordProcessorOptions = {},
  ) {
    this.windowMillis = options.windowMillis ?? DEFAULT_WINDOW_MILLIS;
    this.maxTrackedKeys = options.maxTrackedKeys ?? DEFAULT_MAX_TRACKED_KEYS;
    this.onSuppressed = options.onSuppressed;
    this.now = options.now ?? Date.now;
  }

  onEmit(record: ReadWriteLogRecord, context?: Context): void {
    if (record.eventName === RECORDS_SUPPRESSED_EVENT_NAME) {
      this.delegate.onEmit(record, context);
      return;
    }
    const key = recordKey(record);
    const now = this.now();
    const openWindow = this.windows.get(key);
    if (openWindow && now - openWindow.openedAt < this.windowMillis) {
      openWindow.suppressed += 1;
      return;
    }
    if (openWindow) {
      this.report(openWindow);
    }
    this.windows.delete(key);
    this.windows.set(key, {
      openedAt: now,
      suppressed: 0,
      eventName: record.eventName ?? '',
      level: record.severityText ?? '',
    });
    this.evictOldestWindows();
    this.delegate.onEmit(record, context);
  }

  async forceFlush(options?: ForceFlushOptions): Promise<void> {
    this.reportAllPending();
    await this.delegate.forceFlush(options);
  }

  async shutdown(): Promise<void> {
    this.reportAllPending();
    this.windows.clear();
    await this.delegate.shutdown();
  }

  private evictOldestWindows(): void {
    while (this.windows.size > this.maxTrackedKeys) {
      const [oldestKey, oldestWindow] = this.windows.entries().next().value as [string, DedupWindow];
      this.report(oldestWindow);
      this.windows.delete(oldestKey);
    }
  }

  private reportAllPending(): void {
    this.windows.forEach((openWindow) => {
      this.report(openWindow);
      openWindow.suppressed = 0;
    });
  }

  private report(openWindow: DedupWindow): void {
    if (openWindow.suppressed > 0) {
      this.onSuppressed?.({ eventName: openWindow.eventName, level: openWindow.level, count: openWindow.suppressed });
    }
  }
}
