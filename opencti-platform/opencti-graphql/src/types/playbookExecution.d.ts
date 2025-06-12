import type { Operation } from 'fast-json-patch';
import type { StixBundle } from './stix-2-1-common';

export interface ExecutionEnvelopStep {
  message: string,
  previous_step_id?: string,
  status: 'success' | 'error',
  in_timestamp: string,
  out_timestamp: string,
  duration: number,
  bundle?: StixBundle | null,
  patch?: Operation[],
  error?: string,
}

export interface ExecutionEnvelop {
  playbook_id: string
  playbook_execution_id: string
  last_execution_step: string | undefined
  [k: `step_${string}`]: ExecutionEnvelopStep
}
