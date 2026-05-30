export interface SlaDurationValue {
  millis: number;
  friendly: string;
}

export interface SlaCycleMetrics {
  breached?: boolean;
  paused?: boolean;
  goalDuration: SlaDurationValue;
  elapsedTime: SlaDurationValue;
  remainingTime: SlaDurationValue;
}

export interface SlaValueItem {
  id: string;
  name: string;
  ongoingCycle?: SlaCycleMetrics | null;
  completedCycles?: SlaCycleMetrics[];
}

export interface CaseRfiSlaResult {
  opencti_id: string;
  opencti_name: string;
  jira_key: string;
  sla_data: {
    values: SlaValueItem[];
  };
}

export interface CaseRfiSlaApiResponse {
  results: CaseRfiSlaResult[];
}
