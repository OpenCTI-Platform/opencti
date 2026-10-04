import { FunctionalError } from '../../config/errors';
import type { AuthUser } from '../../types/user';
import { INGESTION_SETINGESTIONS, isUserHasCapability, SETTINGS_SET_ACCESSES, SETTINGS_SETCUSTOMIZATION } from '../../utils/access';
import {
  RECOMMENDATION_ADD_CONNECTOR,
  RECOMMENDATION_ADD_DECAY_RULE,
  RECOMMENDATION_ADD_DENY_LIST,
  RECOMMENDATION_CHANGE_SCHEDULE,
  RECOMMENDATION_KINDS,
  RECOMMENDATION_LOWER_CONFIDENCE,
  RECOMMENDATION_QUARANTINE,
  RECOMMENDATION_RAISE_CONFIDENCE,
  RECOMMENDATION_RETIRE,
  type RecommendationKindValue,
} from './sourceIntelligence-types';

export const MODULES_MODMANAGE = 'MODULES_MODMANAGE';

/**
 * Capabilities a person needs to apply a recommendation kind by hand, whatever its target (a connector, a feed or a
 * user). The autonomy policy applies the kinds it allows without checking them again: allowing a kind requires them all.
 */
export const RECOMMENDATION_KIND_CAPABILITIES: Record<RecommendationKindValue, readonly string[]> = {
  [RECOMMENDATION_RAISE_CONFIDENCE]: [SETTINGS_SET_ACCESSES],
  [RECOMMENDATION_LOWER_CONFIDENCE]: [SETTINGS_SET_ACCESSES],
  [RECOMMENDATION_ADD_DECAY_RULE]: [SETTINGS_SETCUSTOMIZATION],
  [RECOMMENDATION_ADD_DENY_LIST]: [SETTINGS_SETCUSTOMIZATION],
  [RECOMMENDATION_CHANGE_SCHEDULE]: [INGESTION_SETINGESTIONS, MODULES_MODMANAGE],
  [RECOMMENDATION_QUARANTINE]: [SETTINGS_SET_ACCESSES, INGESTION_SETINGESTIONS],
  [RECOMMENDATION_RETIRE]: [INGESTION_SETINGESTIONS, MODULES_MODMANAGE],
  [RECOMMENDATION_ADD_CONNECTOR]: [MODULES_MODMANAGE],
};

/** Capabilities the user lacks to allow the kinds an autonomy policy update adds; kinds already allowed or removed need none. */
export const missingAutonomyCapabilities = (user: AuthUser, currentKinds: readonly string[], nextKinds: readonly RecommendationKindValue[]): string[] => {
  const added = nextKinds.filter((kind) => !currentKinds.includes(kind));
  const required = new Set(added.flatMap((kind) => RECOMMENDATION_KIND_CAPABILITIES[kind]));
  return Array.from(required).filter((capability) => !isUserHasCapability(user, capability));
};

export interface SourceIntelligenceValueWeights {
  uniqueness: number;
  lead_time: number;
  accuracy: number;
  relevance: number;
  impact: number;
  noise: number;
}

export interface SourceIntelligenceThresholds {
  // Below this volume on the reference period, a source gets a scorecard but no tuning recommendation
  min_volume: number;
  low_accuracy: number;
  quarantine_accuracy: number;
  high_accuracy: number;
  raise_confidence_corroboration: number;
  high_noise: number;
  deny_list_min_false_positives: number;
  redundant_overlap: number;
  retire_max_unique_contribution: number;
  stale_feed_hours: number;
  gap_coverage: number;
}

export interface SourceIntelligenceTuning {
  confidence_step: number;
  min_confidence: number;
  noisy_decay_lifetime_days: number;
  deny_list_max_values: number;
  dismiss_cooldown_days: number;
  min_schedule_minutes: number;
}

export interface SourceIntelligenceAutonomy {
  // Allow-list of recommendation kinds the platform may apply without a human (Enterprise Edition)
  auto_apply_kinds: RecommendationKindValue[];
  max_auto_actions_per_run: number;
}

export interface SourceIntelligenceGapSettings {
  window_days: number;
  recent_days: number;
  target_relationships: number;
  target_sources: number;
  max_recommendations: number;
}

export interface SourceIntelligenceSettings {
  recompute_hour_utc: number;
  backfill_days: number;
  snapshot_retention_days: number;
  corroboration_min_other_sources: number;
  false_positive_labels: string[];
  max_scan_objects: number;
  overlap_top: number;
  min_author_volume: number;
  max_author_sources: number;
  min_manual_volume: number;
  max_manual_sources: number;
  value_weights: SourceIntelligenceValueWeights;
  thresholds: SourceIntelligenceThresholds;
  tuning: SourceIntelligenceTuning;
  autonomy: SourceIntelligenceAutonomy;
  gaps: SourceIntelligenceGapSettings;
}

export const DEFAULT_SOURCE_INTELLIGENCE_SETTINGS: SourceIntelligenceSettings = {
  recompute_hour_utc: 2,
  backfill_days: 14,
  snapshot_retention_days: 365,
  corroboration_min_other_sources: 2,
  false_positive_labels: ['false-positive', 'false positive', 'false_positive', 'fp'],
  max_scan_objects: 2000000,
  overlap_top: 10,
  min_author_volume: 10,
  max_author_sources: 500,
  min_manual_volume: 10,
  max_manual_sources: 200,
  value_weights: {
    uniqueness: 0.25,
    lead_time: 0.15,
    accuracy: 0.2,
    relevance: 0.15,
    impact: 0.15,
    noise: 0.1,
  },
  thresholds: {
    min_volume: 50,
    low_accuracy: 0.7,
    quarantine_accuracy: 0.4,
    high_accuracy: 0.95,
    raise_confidence_corroboration: 0.5,
    high_noise: 0.6,
    deny_list_min_false_positives: 10,
    redundant_overlap: 0.9,
    retire_max_unique_contribution: 0.05,
    stale_feed_hours: 72,
    gap_coverage: 50,
  },
  tuning: {
    confidence_step: 15,
    min_confidence: 10,
    noisy_decay_lifetime_days: 30,
    deny_list_max_values: 5000,
    dismiss_cooldown_days: 30,
    min_schedule_minutes: 60,
  },
  autonomy: {
    auto_apply_kinds: [],
    max_auto_actions_per_run: 5,
  },
  gaps: {
    window_days: 90,
    recent_days: 30,
    target_relationships: 50,
    target_sources: 3,
    max_recommendations: 5,
  },
};

type Bounds = { min: number; max: number; integer?: boolean };

const SCALAR_BOUNDS: Record<string, Bounds> = {
  recompute_hour_utc: { min: 0, max: 23, integer: true },
  backfill_days: { min: 0, max: 90, integer: true },
  snapshot_retention_days: { min: 30, max: 1825, integer: true },
  corroboration_min_other_sources: { min: 1, max: 10, integer: true },
  max_scan_objects: { min: 1000, max: 50000000, integer: true },
  overlap_top: { min: 1, max: 50, integer: true },
  min_author_volume: { min: 1, max: 100000, integer: true },
  max_author_sources: { min: 0, max: 5000, integer: true },
  min_manual_volume: { min: 1, max: 100000, integer: true },
  max_manual_sources: { min: 0, max: 2000, integer: true },
};

const NESTED_BOUNDS: Record<'value_weights' | 'thresholds' | 'tuning' | 'autonomy' | 'gaps', Record<string, Bounds>> = {
  value_weights: {
    uniqueness: { min: 0, max: 1 },
    lead_time: { min: 0, max: 1 },
    accuracy: { min: 0, max: 1 },
    relevance: { min: 0, max: 1 },
    impact: { min: 0, max: 1 },
    noise: { min: 0, max: 1 },
  },
  thresholds: {
    min_volume: { min: 0, max: 10000000, integer: true },
    low_accuracy: { min: 0, max: 1 },
    quarantine_accuracy: { min: 0, max: 1 },
    high_accuracy: { min: 0, max: 1 },
    raise_confidence_corroboration: { min: 0, max: 1 },
    high_noise: { min: 0, max: 1 },
    deny_list_min_false_positives: { min: 1, max: 100000, integer: true },
    redundant_overlap: { min: 0, max: 1 },
    retire_max_unique_contribution: { min: 0, max: 1 },
    stale_feed_hours: { min: 1, max: 8760, integer: true },
    gap_coverage: { min: 0, max: 100, integer: true },
  },
  tuning: {
    confidence_step: { min: 1, max: 50, integer: true },
    min_confidence: { min: 0, max: 100, integer: true },
    noisy_decay_lifetime_days: { min: 1, max: 3650, integer: true },
    deny_list_max_values: { min: 1, max: 100000, integer: true },
    dismiss_cooldown_days: { min: 0, max: 365, integer: true },
    min_schedule_minutes: { min: 5, max: 10080, integer: true },
  },
  autonomy: {
    max_auto_actions_per_run: { min: 0, max: 100, integer: true },
  },
  gaps: {
    window_days: { min: 7, max: 365, integer: true },
    recent_days: { min: 1, max: 365, integer: true },
    target_relationships: { min: 1, max: 100000, integer: true },
    target_sources: { min: 1, max: 50, integer: true },
    max_recommendations: { min: 1, max: 20, integer: true },
  },
};

const checkBounds = (path: string, value: unknown, bounds: Bounds): number => {
  if (typeof value !== 'number' || Number.isNaN(value) || !Number.isFinite(value)) {
    throw FunctionalError('Invalid source intelligence setting, a number is expected', { path });
  }
  if (bounds.integer && !Number.isInteger(value)) {
    throw FunctionalError('Invalid source intelligence setting, an integer is expected', { path });
  }
  if (value < bounds.min || value > bounds.max) {
    throw FunctionalError('Invalid source intelligence setting, value out of bounds', { path, min: bounds.min, max: bounds.max });
  }
  return value;
};

/**
 * Merge stored settings over the defaults: new settings keys introduced by later versions get their default value,
 * unknown keys are dropped.
 */
export const resolveSourceIntelligenceSettings = (stored: unknown): SourceIntelligenceSettings => {
  const defaults = DEFAULT_SOURCE_INTELLIGENCE_SETTINGS;
  const raw = (stored && typeof stored === 'object' ? stored : {}) as Record<string, any>;
  const pickScalar = (key: keyof typeof SCALAR_BOUNDS) => {
    const value = raw[key];
    const bounds = SCALAR_BOUNDS[key];
    if (typeof value === 'number' && Number.isFinite(value) && value >= bounds.min && value <= bounds.max) {
      return bounds.integer ? Math.round(value) : value;
    }
    return (defaults as unknown as Record<string, number>)[key];
  };
  const pickNested = <K extends keyof typeof NESTED_BOUNDS>(key: K) => {
    const defaultGroup = defaults[key] as unknown as Record<string, unknown>;
    const storedGroup = (raw[key] && typeof raw[key] === 'object' ? raw[key] : {}) as Record<string, unknown>;
    const result: Record<string, unknown> = { ...defaultGroup };
    Object.entries(NESTED_BOUNDS[key]).forEach(([subKey, bounds]) => {
      const value = storedGroup[subKey];
      if (typeof value === 'number' && Number.isFinite(value) && value >= bounds.min && value <= bounds.max) {
        result[subKey] = bounds.integer ? Math.round(value) : value;
      }
    });
    return result;
  };
  const autonomy = pickNested('autonomy') as unknown as SourceIntelligenceAutonomy;
  const storedKinds = Array.isArray(raw.autonomy?.auto_apply_kinds) ? raw.autonomy.auto_apply_kinds : defaults.autonomy.auto_apply_kinds;
  autonomy.auto_apply_kinds = storedKinds.filter((kind: string) => (RECOMMENDATION_KINDS as readonly string[]).includes(kind));
  const labels = Array.isArray(raw.false_positive_labels)
    ? raw.false_positive_labels.filter((l: unknown) => typeof l === 'string' && l.trim().length > 0).map((l: string) => l.trim().toLowerCase())
    : defaults.false_positive_labels;
  return {
    recompute_hour_utc: pickScalar('recompute_hour_utc'),
    backfill_days: pickScalar('backfill_days'),
    snapshot_retention_days: pickScalar('snapshot_retention_days'),
    corroboration_min_other_sources: pickScalar('corroboration_min_other_sources'),
    false_positive_labels: labels,
    max_scan_objects: pickScalar('max_scan_objects'),
    overlap_top: pickScalar('overlap_top'),
    min_author_volume: pickScalar('min_author_volume'),
    max_author_sources: pickScalar('max_author_sources'),
    min_manual_volume: pickScalar('min_manual_volume'),
    max_manual_sources: pickScalar('max_manual_sources'),
    value_weights: pickNested('value_weights') as unknown as SourceIntelligenceValueWeights,
    thresholds: pickNested('thresholds') as unknown as SourceIntelligenceThresholds,
    tuning: pickNested('tuning') as unknown as SourceIntelligenceTuning,
    autonomy,
    gaps: pickNested('gaps') as unknown as SourceIntelligenceGapSettings,
  };
};

/**
 * Strict validation of a settings update coming from the API: every provided key must be known and in bounds.
 * Returns the merged settings ready to be stored.
 */
export const validateSourceIntelligenceSettingsInput = (current: SourceIntelligenceSettings, input: Record<string, any>): SourceIntelligenceSettings => {
  const merged: Record<string, any> = structuredClone(current);
  Object.entries(input).forEach(([key, value]) => {
    if (value === undefined || value === null) {
      return;
    }
    if (key in SCALAR_BOUNDS) {
      merged[key] = checkBounds(key, value, SCALAR_BOUNDS[key]);
      return;
    }
    if (key === 'false_positive_labels') {
      if (!Array.isArray(value) || value.length > 50 || value.some((l) => typeof l !== 'string' || l.trim().length === 0 || l.length > 128)) {
        throw FunctionalError('Invalid source intelligence setting, a list of up to 50 labels is expected', { path: key });
      }
      merged[key] = [...new Set(value.map((l: string) => l.trim().toLowerCase()))];
      return;
    }
    if (key in NESTED_BOUNDS) {
      if (typeof value !== 'object' || Array.isArray(value)) {
        throw FunctionalError('Invalid source intelligence setting, an object is expected', { path: key });
      }
      const groupBounds = NESTED_BOUNDS[key as keyof typeof NESTED_BOUNDS];
      Object.entries(value as Record<string, unknown>).forEach(([subKey, subValue]) => {
        if (subValue === undefined || subValue === null) {
          return;
        }
        if (key === 'autonomy' && subKey === 'auto_apply_kinds') {
          if (!Array.isArray(subValue) || subValue.some((k) => !(RECOMMENDATION_KINDS as readonly string[]).includes(k as string))) {
            throw FunctionalError('Invalid source intelligence setting, unknown recommendation kind', { path: `${key}.${subKey}` });
          }
          merged[key][subKey] = [...new Set(subValue as string[])];
          return;
        }
        const bounds = groupBounds[subKey];
        if (!bounds) {
          throw FunctionalError('Invalid source intelligence setting, unknown key', { path: `${key}.${subKey}` });
        }
        merged[key][subKey] = checkBounds(`${key}.${subKey}`, subValue, bounds);
      });
      return;
    }
    throw FunctionalError('Invalid source intelligence setting, unknown key', { path: key });
  });
  const settings = merged as SourceIntelligenceSettings;
  if (settings.thresholds.quarantine_accuracy > settings.thresholds.low_accuracy) {
    throw FunctionalError('Invalid source intelligence setting, quarantine accuracy must be lower than low accuracy', { path: 'thresholds.quarantine_accuracy' });
  }
  if (settings.thresholds.low_accuracy > settings.thresholds.high_accuracy) {
    throw FunctionalError('Invalid source intelligence setting, low accuracy must be lower than high accuracy', { path: 'thresholds.low_accuracy' });
  }
  if (settings.gaps.recent_days > settings.gaps.window_days) {
    throw FunctionalError('Invalid source intelligence setting, recent days must be lower than the gap window', { path: 'gaps.recent_days' });
  }
  const weightsSum = Object.values(settings.value_weights).reduce((acc, w) => acc + w, 0);
  if (weightsSum <= 0) {
    throw FunctionalError('Invalid source intelligence setting, at least one value weight must be positive', { path: 'value_weights' });
  }
  return settings;
};
