import type {
  SlaDurationSnapshot,
  SlaExpiryAlertItem,
  SlaExpiryCountdown,
  SlaExpiryPhase,
  SlaExpiryPhaseStyle,
} from './slaExpiryTypes';

/** Fixed pill width so expand/collapse does not shift horizontally under the search field. */
export const SLA_ALERT_PILL_WIDTH_PX = 520;

const PHASE_COLORS: Record<SlaExpiryPhase, { main: string; soft: string }> = {
  green: { main: '#12A20D', soft: '#E2F3E1' },
  yellow: { main: '#FDE604', soft: '#FEFCE0' },
  orange: { main: '#FF8B00', soft: '#FFF1E0' },
  red: { main: '#DA2E3D', soft: '#FAE5E7' },
  brown: { main: '#975321', soft: '#F2EAE4' },
};

export interface SlaDurationMetrics {
  goalDurationMs: number;
  elapsedTimeMs: number;
  remainingTimeMs: number;
}

export const getSlaDurationMetricsAt = (
  duration: SlaDurationSnapshot,
  nowMs: number = Date.now(),
): SlaDurationMetrics => {
  const deltaMs = nowMs - duration.fetchedAtMs;
  return {
    goalDurationMs: duration.goalDurationMs,
    elapsedTimeMs: duration.elapsedTimeMs + deltaMs,
    remainingTimeMs: duration.remainingTimeMs - deltaMs,
  };
};

export const getSlaExpiryPhaseFromMetrics = (
  goalDurationMs: number,
  elapsedTimeMs: number,
  remainingTimeMs: number,
  breached: boolean = false,
): SlaExpiryPhase => {
  if (breached || remainingTimeMs <= 0 || goalDurationMs <= 0) {
    return 'brown';
  }

  const progress = elapsedTimeMs / goalDurationMs;

  if (progress < 0.25) {
    return 'green';
  }
  if (progress < 0.5) {
    return 'yellow';
  }
  if (progress < 0.75) {
    return 'orange';
  }
  return 'red';
};

export const getSlaExpiryPhaseStyle = (
  item: SlaExpiryAlertItem,
  nowMs: number = Date.now(),
): SlaExpiryPhaseStyle => {
  const metrics = getSlaDurationMetricsAt(item.duration, nowMs);
  const phase = getSlaExpiryPhaseFromMetrics(
    metrics.goalDurationMs,
    metrics.elapsedTimeMs,
    metrics.remainingTimeMs,
    item.duration.breached ?? false,
  );
  return { phase, ...PHASE_COLORS[phase] };
};

const msToCountdown = (durationMs: number): SlaExpiryCountdown => {
  const totalSeconds = Math.floor(Math.max(0, durationMs) / 1000);
  return {
    hours: Math.floor(totalSeconds / 3600),
    minutes: Math.floor((totalSeconds % 3600) / 60),
    seconds: totalSeconds % 60,
  };
};

export const getSlaExpiryRemainingCountdown = (
  item: SlaExpiryAlertItem,
  nowMs: number = Date.now(),
): SlaExpiryCountdown => {
  const { remainingTimeMs } = getSlaDurationMetricsAt(item.duration, nowMs);
  return msToCountdown(remainingTimeMs);
};

export const getSlaExpiryOverdueCountdown = (
  item: SlaExpiryAlertItem,
  nowMs: number = Date.now(),
): SlaExpiryCountdown => {
  const { remainingTimeMs } = getSlaDurationMetricsAt(item.duration, nowMs);
  return msToCountdown(Math.abs(remainingTimeMs));
};

export const padCountdownUnit = (value: number): string => String(value).padStart(2, '0');

export const SLA_EXPIRY_EXPIRED_PREFIX = '−';

export const getSlaExpiryTitleMessageKey = (phase: SlaExpiryPhase): string => {
  switch (phase) {
    case 'brown':
      return 'Expired';
    case 'green':
      return 'Within SLA';
    case 'yellow':
      return 'SLA Active';
    case 'orange':
    case 'red':
      return 'SLA Expiring Soon';
    default:
      return 'SLA Expiring Soon';
  }
};

export const formatSlaExpiryCountdownUnits = (
  countdown: SlaExpiryCountdown,
): string[] => [
  padCountdownUnit(countdown.hours),
  padCountdownUnit(countdown.minutes),
  padCountdownUnit(countdown.seconds),
];

export const compareSlaExpiryUrgency = (
  a: SlaExpiryAlertItem,
  b: SlaExpiryAlertItem,
  nowMs: number = Date.now(),
): number => {
  const remainingA = getSlaDurationMetricsAt(a.duration, nowMs).remainingTimeMs;
  const remainingB = getSlaDurationMetricsAt(b.duration, nowMs).remainingTimeMs;

  if (remainingA !== remainingB) {
    return remainingA - remainingB;
  }

  return a.id.localeCompare(b.id);
};
