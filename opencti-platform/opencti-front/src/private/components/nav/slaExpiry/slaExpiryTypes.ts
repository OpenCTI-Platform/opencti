export type SlaExpiryPhase = 'green' | 'yellow' | 'orange' | 'red' | 'brown';

export interface SlaDurationSnapshot {
  goalDurationMs: number;
  elapsedTimeMs: number;
  remainingTimeMs: number;
  fetchedAtMs: number;
  breached?: boolean;
}

export interface SlaExpiryAlertItem {
  id: string;
  categoryLabel: string;
  title: string;
  duration: SlaDurationSnapshot;
}

export interface SlaExpiryCountdown {
  hours: number;
  minutes: number;
  seconds: number;
}

export interface SlaExpiryPhaseStyle {
  phase: SlaExpiryPhase;
  main: string;
  soft: string;
}
