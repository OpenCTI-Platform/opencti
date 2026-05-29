import type {
  SlaExpiryCountdown,
  SlaExpiryPhase,
  SlaExpiryPhaseStyle,
  SlaExpiryWindow,
} from './slaExpiryTypes';

const PHASE_COLORS: Record<SlaExpiryPhase, { main: string; soft: string }> = {
  green: { main: '#16a34a', soft: '#dcfce7' },
  blue: { main: '#2563eb', soft: '#dbeafe' },
  orange: { main: '#ea580c', soft: '#ffedd5' },
  red: { main: '#dc2626', soft: '#fee2e2' },
  brown: { main: '#92400e', soft: '#fef3c7' },
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
    return 'blue';
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

export const getSlaExpiryCountdown = (
  endTime: string,
  nowMs: number = Date.now(),
): SlaExpiryCountdown => {
  const endMs = new Date(endTime).getTime();
  const remainingMs = Math.max(0, endMs - nowMs);

  const totalSeconds = Math.floor(remainingMs / 1000);
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  return { days, hours, minutes, seconds };
};

export const padCountdownUnit = (value: number): string => String(value).padStart(2, '0');

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
