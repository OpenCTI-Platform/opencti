import type { MigrationSet } from 'migrate';
import { meterManager } from '../config/tracing';

export class MigrationsMetricsRecorder {
  constructor(
    meter: typeof meterManager,
    migrationSet: MigrationSet,
  ) {
    this.meter = meter;
    this.set = migrationSet;
    this.set.on('migration', (migration) => {
      this.startTimestamps[migration.title] = Date.now();
    });
  }

  /**
   * Telemetry: report migration metrics.
   */
  record() {
    this.set.migrations.forEach((migration) => {
      const endTimestamp = migration.timestamp ?? Date.now();
      const status = migration.timestamp ? 'success' : 'failed';
      if (migration.title in this.startTimestamps) {
        const migrationDurationSecs = Math.floor((endTimestamp - this.startTimestamps[migration.title]) / 1000);
        this.meter.migrationDuration(migrationDurationSecs, {
          migrationTitle: migration.title,
          status,
        });
      }
    });
  }

  private meter: typeof meterManager;
  private set: MigrationSet;
  private startTimestamps: Record<string, number> = {};
}
