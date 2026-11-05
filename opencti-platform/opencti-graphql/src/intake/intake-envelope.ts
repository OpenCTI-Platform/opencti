import { OPENCTI_SYSTEM_UUID } from '../schema/general';
import type { AuthContext, AuthUser } from '../types/user';
import { INTAKE_HEADERS } from './intake-context-headers';

// The envelope of an ingestion write: what a worker's request carries in headers, a push message
// carries in its fields (push_handler.py), and a retained write keeps to run again under the same
// context (intake-context.ts). No platform import beyond the types: the sequencer's stores use it.

export interface IntakeEnvelope {
  // The writer (a platform or internal user id); absent: the system user (the worker wrote with its own token)
  user_id?: string;
  applicant_id?: string;
  work_id?: string;
  // Absent: the applicant's own draft; '' : live
  draft_id?: string;
  event_id?: string;
  playbook_id?: string;
  synchronized?: boolean;
  previous_standard?: string;
  retry_number?: number;
}

// The headers pycti sends for an envelope: a header is sent only when its value is set (requests
// drops the None ones), the synchronized one always ("true" / "false"), the retry number from 0
export const intakeHeadersOf = (envelope: IntakeEnvelope): Record<string, string> => {
  const headers: Record<string, string> = {};
  const set = (name: string, value: unknown) => {
    if (value !== null && value !== undefined) {
      headers[name] = String(value);
    }
  };
  set(INTAKE_HEADERS.work, envelope.work_id);
  set(INTAKE_HEADERS.draft, envelope.draft_id);
  set(INTAKE_HEADERS.event, envelope.event_id);
  set(INTAKE_HEADERS.previousStandard, envelope.previous_standard);
  set(INTAKE_HEADERS.applicant, envelope.applicant_id);
  set(INTAKE_HEADERS.playbook, envelope.playbook_id);
  headers[INTAKE_HEADERS.synchronized] = envelope.synchronized === true ? 'true' : 'false';
  headers[INTAKE_HEADERS.retry] = String(envelope.retry_number ?? 0);
  return headers;
};

// The envelope of the push message (the fields the worker reads from it, push_handler.py)
export const intakeEnvelopeOfMessage = (message: Record<string, any>): IntakeEnvelope => ({
  user_id: message.user_id ?? undefined,
  applicant_id: message.applicant_id ?? undefined,
  work_id: message.work_id ?? undefined,
  draft_id: message.draft_id ?? undefined,
  event_id: message.event_id ?? undefined,
  playbook_id: message.playbook_id ?? undefined,
  synchronized: message.synchronized === true,
  previous_standard: message.previous_standard ?? undefined,
  retry_number: message.retry_number ?? undefined,
});

// The envelope a write runs under, read back from its context: kept by a retained write
export const intakeEnvelopeOf = (context: AuthContext, user: AuthUser): IntakeEnvelope => {
  const mutable = context as any;
  const realAuthentication = mutable.real_authentication_id;
  return {
    user_id: realAuthentication && realAuthentication !== OPENCTI_SYSTEM_UUID ? realAuthentication : undefined,
    applicant_id: user.origin?.applicant_id,
    work_id: mutable.workId,
    draft_id: mutable.draft_context,
    event_id: mutable.eventId,
    playbook_id: user.origin?.playbook_id,
    synchronized: mutable.synchronizedUpsert === true,
    previous_standard: mutable.previousStandard,
    retry_number: user.origin?.call_retry_number !== undefined ? Number(user.origin.call_retry_number) : undefined,
  };
};
