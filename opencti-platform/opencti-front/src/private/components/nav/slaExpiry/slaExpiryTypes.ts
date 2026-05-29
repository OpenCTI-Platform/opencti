export type SlaExpiryPhase = 'green' | 'blue' | 'orange' | 'red' | 'brown';

export interface SlaExpiryWindow {
  startTime: string;
  endTime: string;
}

export interface SlaExpiryAlertItem extends SlaExpiryWindow {
  id: string;
  categoryLabel: string;
  title: string;
}

export interface SlaExpiryCountdown {
  days: number;
  hours: number;
  minutes: number;
  seconds: number;
}

export interface SlaExpiryPhaseStyle {
  phase: SlaExpiryPhase;
  main: string;
  soft: string;
}
