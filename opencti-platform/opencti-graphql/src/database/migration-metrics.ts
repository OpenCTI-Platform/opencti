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
      const endTimestamp = migration.timestamp ?? 0;
      if (migration.title in this.startTimestamps && endTimestamp > 0) {
        const migrationDurationSecs = Math.floor((endTimestamp - this.startTimestamps[migration.title]) / 1000);
        this.meter.migrationDuration(migrationDurationSecs, {
          migrationTitle: migration.title,
        });
      }
    });
  };

  private meter: typeof meterManager;
  private set: MigrationSet;
  private startTimestamps: Record<string, number> = {};
}
