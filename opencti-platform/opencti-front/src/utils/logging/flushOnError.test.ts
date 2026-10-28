import { describe, expect, it, vi } from 'vitest';
import type { LogRecordProcessor, ReadWriteLogRecord } from '@opentelemetry/sdk-logs';
import { flushOnError } from './loggerProvider';
import { SEVERITY_NUMBERS } from './logger';

const buildDelegate = () => ({
  onEmit: vi.fn(),
  forceFlush: vi.fn().mockResolvedValue(undefined),
  shutdown: vi.fn().mockResolvedValue(undefined),
}) as unknown as LogRecordProcessor & { onEmit: ReturnType<typeof vi.fn>; forceFlush: ReturnType<typeof vi.fn> };

describe('flushOnError', () => {
  it('flushes right away after an ERROR record', () => {
    const delegate = buildDelegate();
    flushOnError(delegate).onEmit({ severityNumber: SEVERITY_NUMBERS.ERROR } as ReadWriteLogRecord);

    expect(delegate.onEmit).toHaveBeenCalledTimes(1);
    expect(delegate.forceFlush).toHaveBeenCalledTimes(1);
  });

  it('leaves lower levels to the batch delay', () => {
    const delegate = buildDelegate();
    flushOnError(delegate).onEmit({ severityNumber: SEVERITY_NUMBERS.WARN } as ReadWriteLogRecord);

    expect(delegate.onEmit).toHaveBeenCalledTimes(1);
    expect(delegate.forceFlush).not.toHaveBeenCalled();
  });
});
