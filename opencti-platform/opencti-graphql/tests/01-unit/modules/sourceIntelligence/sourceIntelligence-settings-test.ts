import { describe, expect, it } from 'vitest';
import type { AuthUser } from '../../../../src/types/user';
import {
  DEFAULT_SOURCE_INTELLIGENCE_SETTINGS,
  missingAutonomyCapabilities,
  RECOMMENDATION_KIND_CAPABILITIES,
  resolveSourceIntelligenceSettings,
  validateSourceIntelligenceSettingsInput,
} from '../../../../src/modules/sourceIntelligence/sourceIntelligence-settings';
import { RECOMMENDATION_KINDS } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-types';

const userWith = (...capabilities: string[]) => ({ id: 'user', capabilities: capabilities.map((name) => ({ name })) }) as unknown as AuthUser;

describe('Source intelligence autonomy policy capabilities', () => {
  it('should name the capabilities of every recommendation kind', () => {
    RECOMMENDATION_KINDS.forEach((kind) => {
      expect(RECOMMENDATION_KIND_CAPABILITIES[kind].length).toBeGreaterThan(0);
    });
  });

  it('should require the capabilities of the kinds an update adds', () => {
    const customizer = userWith('SETTINGS_SETCUSTOMIZATION');
    expect(missingAutonomyCapabilities(customizer, [], ['retire']).sort()).toEqual(['INGESTION_SETINGESTIONS', 'MODULES_MODMANAGE']);
    expect(missingAutonomyCapabilities(customizer, [], ['raise_confidence', 'quarantine']).sort()).toEqual(['INGESTION_SETINGESTIONS', 'SETTINGS_SETACCESSES']);
    expect(missingAutonomyCapabilities(customizer, [], ['add_decay_rule', 'add_deny_list'])).toEqual([]);
  });

  it('should not require anything to keep or remove kinds already allowed', () => {
    const customizer = userWith('SETTINGS_SETCUSTOMIZATION');
    expect(missingAutonomyCapabilities(customizer, ['retire', 'add_connector'], ['retire'])).toEqual([]);
    expect(missingAutonomyCapabilities(customizer, ['retire'], [])).toEqual([]);
  });

  it('should let a user holding every capability, or the bypass, allow any kind', () => {
    const allKinds = [...RECOMMENDATION_KINDS];
    const administrator = userWith('SETTINGS_SETCUSTOMIZATION', 'SETTINGS_SETACCESSES', 'INGESTION_SETINGESTIONS', 'MODULES_MODMANAGE');
    expect(missingAutonomyCapabilities(administrator, [], allKinds)).toEqual([]);
    expect(missingAutonomyCapabilities(userWith('BYPASS'), [], allKinds)).toEqual([]);
  });
});

describe('Source intelligence settings', () => {
  it('should fall back on the defaults for missing, invalid or unknown stored values', () => {
    expect(resolveSourceIntelligenceSettings(null)).toEqual(DEFAULT_SOURCE_INTELLIGENCE_SETTINGS);
    const resolved = resolveSourceIntelligenceSettings({
      recompute_hour_utc: 30,
      backfill_days: 7,
      unknown_key: true,
      thresholds: { low_accuracy: 0.6, high_noise: 'high' },
      autonomy: { auto_apply_kinds: ['lower_confidence', 'delete_everything'] },
      false_positive_labels: [' FP ', '', 42],
    });
    expect(resolved.recompute_hour_utc).toEqual(DEFAULT_SOURCE_INTELLIGENCE_SETTINGS.recompute_hour_utc);
    expect(resolved.backfill_days).toEqual(7);
    expect(resolved).not.toHaveProperty('unknown_key');
    expect(resolved.thresholds.low_accuracy).toEqual(0.6);
    expect(resolved.thresholds.high_noise).toEqual(DEFAULT_SOURCE_INTELLIGENCE_SETTINGS.thresholds.high_noise);
    expect(resolved.autonomy.auto_apply_kinds).toEqual(['lower_confidence']);
    expect(resolved.false_positive_labels).toEqual(['fp']);
  });

  it('should merge a valid update', () => {
    const updated = validateSourceIntelligenceSettingsInput(DEFAULT_SOURCE_INTELLIGENCE_SETTINGS, {
      recompute_hour_utc: 4,
      false_positive_labels: ['False-Positive', 'false-positive', 'benign'],
      thresholds: { min_volume: 10 },
      autonomy: { auto_apply_kinds: ['add_decay_rule', 'add_decay_rule'], max_auto_actions_per_run: 2 },
    });
    expect(updated.recompute_hour_utc).toEqual(4);
    expect(updated.false_positive_labels).toEqual(['false-positive', 'benign']);
    expect(updated.thresholds.min_volume).toEqual(10);
    expect(updated.thresholds.low_accuracy).toEqual(DEFAULT_SOURCE_INTELLIGENCE_SETTINGS.thresholds.low_accuracy);
    expect(updated.autonomy).toEqual({ auto_apply_kinds: ['add_decay_rule'], max_auto_actions_per_run: 2 });
    // The current settings are never mutated
    expect(DEFAULT_SOURCE_INTELLIGENCE_SETTINGS.recompute_hour_utc).toEqual(2);
  });

  it('should reject unknown keys, out of bounds values and incoherent thresholds', () => {
    const current = DEFAULT_SOURCE_INTELLIGENCE_SETTINGS;
    expect(() => validateSourceIntelligenceSettingsInput(current, { unknown: 1 })).toThrow();
    expect(() => validateSourceIntelligenceSettingsInput(current, { recompute_hour_utc: 24 })).toThrow();
    expect(() => validateSourceIntelligenceSettingsInput(current, { backfill_days: 1.5 })).toThrow();
    expect(() => validateSourceIntelligenceSettingsInput(current, { thresholds: { unknown: 1 } })).toThrow();
    expect(() => validateSourceIntelligenceSettingsInput(current, { value_weights: { accuracy: 2 } })).toThrow();
    expect(() => validateSourceIntelligenceSettingsInput(current, { autonomy: { auto_apply_kinds: ['delete'] } })).toThrow();
    expect(() => validateSourceIntelligenceSettingsInput(current, { false_positive_labels: [''] })).toThrow();
    expect(() => validateSourceIntelligenceSettingsInput(current, { thresholds: { quarantine_accuracy: 0.8, low_accuracy: 0.7 } })).toThrow();
    expect(() => validateSourceIntelligenceSettingsInput(current, { thresholds: { low_accuracy: 0.99, high_accuracy: 0.9 } })).toThrow();
    expect(() => validateSourceIntelligenceSettingsInput(current, { gaps: { recent_days: 120, window_days: 90 } })).toThrow();
    expect(() => validateSourceIntelligenceSettingsInput(current, {
      value_weights: { uniqueness: 0, lead_time: 0, accuracy: 0, relevance: 0, impact: 0, noise: 0 },
    })).toThrow();
  });
});
