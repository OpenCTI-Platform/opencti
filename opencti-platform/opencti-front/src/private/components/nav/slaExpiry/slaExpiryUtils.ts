import type {
  SlaExpiryCountdown,
  SlaExpiryPhase,
  SlaExpiryPhaseStyle,
  SlaExpiryWindow,
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

export const getSlaExpiryPhase = (
  startTime: string,
  endTime: string,
  nowMs: number = Date.now(),
): SlaExpiryPhase => {
  const startMs = new Date(startTime).getTime();
  const endMs = new Date(endTime).getTime();

  if (Number.isNaN(startMs) || Number.isNaN(endMs) || endMs <= startMs) {
    return 'brown';
  }

  if (nowMs >= endMs) {
    return 'brown';
  }

  if (nowMs < startMs) {
    return 'green';
  }

  const progress = (nowMs - startMs) / (endMs - startMs);

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
  window: SlaExpiryWindow,
  nowMs: number = Date.now(),
): SlaExpiryPhaseStyle => {
  const phase = getSlaExpiryPhase(window.startTime, window.endTime, nowMs);
  return { phase, ...PHASE_COLORS[phase] };
};

const msToCountdown = (durationMs: number): SlaExpiryCountdown => {
  const totalSeconds = Math.floor(Math.max(0, durationMs) / 1000);
  return {
    days: Math.floor(totalSeconds / 86400),
    hours: Math.floor((totalSeconds % 86400) / 3600),
    minutes: Math.floor((totalSeconds % 3600) / 60),
    seconds: totalSeconds % 60,
  };
};

export const getSlaExpiryCountdown = (
  endTime: string,
  nowMs: number = Date.now(),
): SlaExpiryCountdown => {
  const endMs = new Date(endTime).getTime();
  return msToCountdown(endMs - nowMs);
};

export const getSlaExpiryOverdueElapsed = (
  endTime: string,
  nowMs: number = Date.now(),
): SlaExpiryCountdown => {
  const endMs = new Date(endTime).getTime();
  return msToCountdown(nowMs - endMs);
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
  padCountdownUnit(countdown.days),
  padCountdownUnit(countdown.hours),
  padCountdownUnit(countdown.minutes),
  padCountdownUnit(countdown.seconds),
];

export const compareSlaExpiryUrgency = (
  a: SlaExpiryWindow,
  b: SlaExpiryWindow,
  nowMs: number = Date.now(),
): number => {
  const endA = new Date(a.endTime).getTime();
  const endB = new Date(b.endTime).getTime();
  const remainingA = endA - nowMs;
  const remainingB = endB - nowMs;

  if (remainingA !== remainingB) {
    return remainingA - remainingB;
  }

  return endA - endB;
};
