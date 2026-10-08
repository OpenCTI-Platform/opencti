import { describe, expect, it, vi } from 'vitest';
import type { LogRecordProcessor, ReadWriteLogRecord } from '@opentelemetry/sdk-logs';
import { DedupLogRecordProcessor, RECORDS_SUPPRESSED_EVENT_NAME } from './DedupLogRecordProcessor';

const buildRecord = (overrides: Partial<ReadWriteLogRecord> = {}) => ({
  severityText: 'ERROR',
  eventName: 'opencti.frontend.component_crashed',
  body: 'React component tree crashed',
  ...overrides,
} as ReadWriteLogRecord);

const buildDelegate = () => ({
  onEmit: vi.fn(),
  forceFlush: vi.fn().mockResolvedValue(undefined),
  shutdown: vi.fn().mockResolvedValue(undefined),
}) as unknown as LogRecordProcessor & { onEmit: ReturnType<typeof vi.fn> };

describe('DedupLogRecordProcessor', () => {
  it('forwards the first record of a window', () => {
    const delegate = buildDelegate();
    const processor = new DedupLogRecordProcessor(delegate);

    processor.onEmit(buildRecord());

    expect(delegate.onEmit).toHaveBeenCalledTimes(1);
  });

  it('suppresses identical records inside the window', () => {
    const delegate = buildDelegate();
    let now = 0;
    const processor = new DedupLogRecordProcessor(delegate, { windowMillis: 1000, now: () => now });

    processor.onEmit(buildRecord());
    now = 500;
    processor.onEmit(buildRecord());
    processor.onEmit(buildRecord());

    expect(delegate.onEmit).toHaveBeenCalledTimes(1);
  });

  it('keeps distinct records independent', () => {
    const delegate = buildDelegate();
    const processor = new DedupLogRecordProcessor(delegate);

    processor.onEmit(buildRecord());
    processor.onEmit(buildRecord({ body: 'Another failure' }));
    processor.onEmit(buildRecord({ severityText: 'WARN' }));

    expect(delegate.onEmit).toHaveBeenCalledTimes(3);
  });

  it('keeps records with distinct exceptions independent', () => {
    const delegate = buildDelegate();
    const processor = new DedupLogRecordProcessor(delegate);

    processor.onEmit(buildRecord({ attributes: { 'exception.type': 'TypeError', 'exception.message': 'value.split is not a function' } }));
    processor.onEmit(buildRecord({ attributes: { 'exception.type': 'TypeError', 'exception.message': 'value.map is not a function' } }));
    processor.onEmit(buildRecord({ attributes: { 'exception.type': 'RangeError', 'exception.message': 'value.map is not a function' } }));
    processor.onEmit(buildRecord({ attributes: { 'exception.type': 'RangeError', 'exception.message': 'value.map is not a function' } }));

    expect(delegate.onEmit).toHaveBeenCalledTimes(3);
  });

  it('reports the suppressed count when the window closes', () => {
    const delegate = buildDelegate();
    const onSuppressed = vi.fn();
    let now = 0;
    const processor = new DedupLogRecordProcessor(delegate, { windowMillis: 1000, onSuppressed, now: () => now });

    processor.onEmit(buildRecord());
    now = 500;
    processor.onEmit(buildRecord());
    processor.onEmit(buildRecord());
    now = 1500;
    processor.onEmit(buildRecord());

    expect(delegate.onEmit).toHaveBeenCalledTimes(2);
    expect(onSuppressed).toHaveBeenCalledWith({
      eventName: 'opencti.frontend.component_crashed',
      level: 'ERROR',
      count: 2,
    });
  });

  it('reports pending suppressions on force flush, once', async () => {
    const delegate = buildDelegate();
    const onSuppressed = vi.fn();
    const processor = new DedupLogRecordProcessor(delegate, { onSuppressed });

    processor.onEmit(buildRecord());
    processor.onEmit(buildRecord());
    await processor.forceFlush();
    await processor.forceFlush();

    expect(onSuppressed).toHaveBeenCalledTimes(1);
    expect(onSuppressed).toHaveBeenCalledWith(expect.objectContaining({ count: 1 }));
    expect(delegate.forceFlush).toHaveBeenCalledTimes(2);
  });

  it('never deduplicates the suppression report itself', () => {
    const delegate = buildDelegate();
    const processor = new DedupLogRecordProcessor(delegate);
    const report = buildRecord({ eventName: RECORDS_SUPPRESSED_EVENT_NAME, severityText: 'INFO', body: 'Duplicate log records suppressed' });

    processor.onEmit(report);
    processor.onEmit(report);

    expect(delegate.onEmit).toHaveBeenCalledTimes(2);
  });

  it('bounds the number of tracked windows', () => {
    const delegate = buildDelegate();
    const onSuppressed = vi.fn();
    const processor = new DedupLogRecordProcessor(delegate, { maxTrackedKeys: 2, onSuppressed });

    processor.onEmit(buildRecord({ body: 'first', eventName: 'opencti.frontend.first' }));
    processor.onEmit(buildRecord({ body: 'first', eventName: 'opencti.frontend.first' }));
    processor.onEmit(buildRecord({ body: 'second' }));
    processor.onEmit(buildRecord({ body: 'third' }));

    expect(onSuppressed).toHaveBeenCalledWith(expect.objectContaining({ eventName: 'opencti.frontend.first', count: 1 }));
  });

  it('shuts the delegate down', async () => {
    const delegate = buildDelegate();
    const processor = new DedupLogRecordProcessor(delegate);

    processor.onEmit(buildRecord());
    await processor.shutdown();

    expect(delegate.shutdown).toHaveBeenCalledTimes(1);
  });
});
