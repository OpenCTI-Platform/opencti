import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { FileStore, MigrationSet } from 'migrate';
import { MigrationsMetricsRecorder } from '../../../src/database/migration-metrics';
import type { meterManager } from '../../../src/config/tracing';

describe('MigrationMetricsRecorder', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('reports duration metric for finished migrations', () => {
    const set = new MigrationSet({} as FileStore);
    const migrationTitle = 'test-migration';
    set.addMigration(migrationTitle, (next: () => void) => {
      next();
    }, () => {});
    const meterSpy = {
      migrationDuration: vi.fn(),
    } as unknown as typeof meterManager;
    const metricsRecorder = new MigrationsMetricsRecorder(meterSpy, set);
    const date = new Date(2026, 1, 1, 13);
    vi.setSystemTime(date);
    const deltaSeconds = 60;
    // Mimic `migrate` lib behaviour
    set.emit('migration', set.migrations[0], 'up');
    set.migrations[0].timestamp = date.getTime() + deltaSeconds * 1000;

    metricsRecorder.record();
    expect(meterSpy.migrationDuration).toHaveBeenCalledWith(deltaSeconds, {
      migrationTitle,
    });
  });
});
